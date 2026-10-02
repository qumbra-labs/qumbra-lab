//! Lab #818: `qumbra-faucet check` and `run` through the REAL binary on a **V6**
//! genesis (format 10). Both loaded the genesis as the L1 base, so both refused
//! every V6 net (`this is a V6 genesis file (format 10): load it as a V6
//! genesis`) — the same class of bug PR #817 fixed in `qumbra-node check`, at
//! the two faucet sites its census named.
//!
//! The genesis is the V6 rehearsal genesis (`GenesisFileV6::new_rehearsal`,
//! what `qumbra-node genesis init --t2` writes); the faucet's key material is
//! the binary's own `keygen` output in a temp dir. The node is keyless, as a
//! faucet's must be (§6.2).

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use qumbra_node::annulet_genesis::AnnuletGenesisFile;
use qumbra_node::genesis_v6::GenesisFileV6;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-faucet")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("i818_faucet_v6_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("data")).expect("temp dir");
    d
}

fn free_port() -> String {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string()
}

fn faucet(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("spawn qumbra-faucet")
}

/// `keygen` into `dir`, a faucet config over `dir/node.toml`, and the
/// `miner_rkm` the faucet's `address` prints for it.
fn stage_faucet(dir: &Path) -> (PathBuf, String) {
    let out = faucet(&["keygen", "--out", dir.to_str().unwrap()]);
    assert!(out.status.success(), "keygen: {}", String::from_utf8_lossy(&out.stderr));
    let cfg = dir.join("faucet.toml");
    std::fs::write(
        &cfg,
        format!(
            "listen_addr = \"{listen}\"\nnode_config = \"{node}\"\nseed_file = \"{seed}\"\n\
             ticket_secret_file = \"{tickets}\"\n",
            listen = free_port(),
            node = dir.join("node.toml").display(),
            seed = dir.join("faucet.seed").display(),
            tickets = dir.join("faucet-tickets.secret").display(),
        ),
    )
    .unwrap();
    let out = faucet(&["address", "--config", cfg.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "address: {stdout} {}", String::from_utf8_lossy(&out.stderr));
    let rkm = stdout
        .lines()
        .find_map(|l| l.strip_prefix("miner_rkm = \"").and_then(|r| r.strip_suffix('"')))
        .unwrap_or_else(|| panic!("no miner_rkm line: {stdout}"))
        .to_string();
    (cfg, rkm)
}

/// The faucet's keyless node config over `genesis` bytes, pinned to `pin`.
/// `rkm` = `Some` makes it a mining node paying the faucet.
fn stage_node(dir: &Path, genesis: &[u8], pin: &str, rkm: Option<&str>) {
    std::fs::write(dir.join("genesis.qmb"), genesis).unwrap();
    let mining = match rkm {
        Some(rkm) => format!("mining = true\nminer_rkm = \"{rkm}\"\n"),
        None => "mining = false\n".to_string(),
    };
    std::fs::write(
        dir.join("node.toml"),
        format!(
            "data_dir = \"{data}\"\nlisten_addr = \"127.0.0.1:0\"\ndial_peers = []\n\
             genesis_file = \"{gen}\"\nexpected_genesis_hash = \"{pin}\"\ncommittee_key_paths = []\n{mining}",
            data = dir.join("data").display(),
            gen = dir.join("genesis.qmb").display(),
        ),
    )
    .unwrap();
}

/// `check` accepts a V6 faucet config and reports the **V6** hash; it still
/// refuses a wrong pin — the L1 base's hash included, since a V6 node pins the
/// V6 hash — and refuses an Annulet genesis by naming the faucet that serves it.
#[test]
fn check_accepts_a_v6_net_and_still_refuses_a_wrong_pin() {
    let dir = tmp("check");
    let (cfg, rkm) = stage_faucet(&dir);
    let v6 = GenesisFileV6::new_rehearsal();
    let check = || faucet(&["check", "--config", cfg.to_str().unwrap()]);

    stage_node(&dir, &v6.to_bytes(), &v6.hash_hex(), Some(&rkm));
    let out = check();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "check refused the V6 faucet config: {stdout} {stderr}");
    assert!(stdout.contains("qumbra-faucet check: OK"), "{stdout}");
    assert!(stdout.contains(&format!("node genesis hash: {}", v6.hash_hex())), "the V6 hash is reported: {stdout}");
    assert!(stdout.contains("committee keys:    0"), "{stdout}");

    for pin in [v6.base.hash_hex(), "00".repeat(32)] {
        stage_node(&dir, &v6.to_bytes(), &pin, Some(&rkm));
        let out = check();
        let why = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "pin {pin} must fail check");
        assert!(!why.contains("load it as a V6 genesis"), "refused as a pin mismatch, not as an L1 base: {why}");
    }

    let annulet = AnnuletGenesisFile::devnet();
    stage_node(&dir, &annulet.to_bytes(), &annulet.hash_hex(), None);
    let out = check();
    let why = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "an Annulet genesis is not this faucet's");
    assert!(why.contains("qumbra-faucet annulet"), "the refusal names the faucet that serves it: {why}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `run` opens a V6 net: the in-process keyless node starts on the V6 genesis
/// and the faucet reaches its running banner with the V6 hash. Before #818 it
/// refused at the genesis load, before the node was ever reached.
#[test]
fn run_starts_on_a_v6_net() {
    let dir = tmp("run");
    let (cfg, _rkm) = stage_faucet(&dir);
    let v6 = GenesisFileV6::new_rehearsal();
    stage_node(&dir, &v6.to_bytes(), &v6.hash_hex(), None);

    let mut child = Command::new(bin())
        .args(["run", "--config", cfg.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qumbra-faucet run");
    let (tx, rx) = mpsc::channel();
    for stream in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    }
    drop(tx);

    let mut seen = Vec::new();
    let mut hash_line = false;
    let mut running = false;
    while let Ok(line) = rx.recv_timeout(Duration::from_secs(120)) {
        hash_line |= line.contains(&format!("genesis hash:   {}", v6.hash_hex()));
        running |= line.contains("qumbra-faucet running");
        seen.push(line);
        if running && hash_line {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let log = seen.join("\n");
    assert!(running, "the faucet never reached its running banner on a V6 net:\n{log}");
    assert!(hash_line, "the banner names the V6 genesis hash:\n{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
