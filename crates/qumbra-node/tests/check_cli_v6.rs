//! Lab #785 F5-6: `qumbra-node check` through the REAL binary on a **V6**
//! genesis — the box run's producer pre-flight, which refused every V6 config
//! (`this is a V6 genesis file (format 10): load it as a V6 genesis`) because
//! `check` loaded the file as its L1 base while `run` dispatches it.
//!
//! The genesis comes from the binary's own `genesis init --t2` (the V6
//! rehearsal genesis and its 21 rehearsal committee key files, written to a
//! temp dir and passed to the config by path); the config is the shape the box
//! script writes for its producer. Nothing starts a node.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("f56_check_v6_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// `genesis init --t2 --out DIR`, returning the printed V6 genesis hash.
fn init_v6(dir: &Path) -> String {
    let out = Command::new(bin()).args(["genesis", "init", "--t2", "--out", dir.to_str().unwrap()]).output().expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "genesis init: {stdout} {}", String::from_utf8_lossy(&out.stderr));
    stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("GENESIS HASH:").map(|h| h.trim().to_string()))
        .unwrap_or_else(|| panic!("no GENESIS HASH line: {stdout}"))
}

/// The box script's producer config over `dir`'s genesis, pinned to `pin`.
fn producer_config(dir: &Path, pin: &str) -> PathBuf {
    let keys: Vec<String> =
        (0..21).map(|i| format!("\"{}\"", dir.join(format!("keys/committee-{i:02}.key")).display())).collect();
    let toml = format!(
        "data_dir = \"{data}\"\nlisten_addr = \"127.0.0.1:39400\"\ngenesis_file = \"{gen}\"\n\
         expected_genesis_hash = \"{pin}\"\ndiscovery_addr = \"127.0.0.1:39401\"\ntelemetry_addr = \"127.0.0.1:39402\"\n\
         metrics_addr = \"127.0.0.1:39404\"\noperator_addr = \"127.0.0.1:39403\"\nmining = true\n\
         miner_rkm = \"{rkm}\"\ncommittee_key_paths = [{keys}]\n",
        data = dir.join("data").display(),
        gen = dir.join("genesis.qmb").display(),
        rkm = "01".repeat(32),
        keys = keys.join(","),
    );
    let path = dir.join(format!("node-{}.toml", &pin[..8]));
    std::fs::write(&path, toml).unwrap();
    path
}

fn check(config: &Path) -> Output {
    Command::new(bin()).args(["check", "--config", config.to_str().unwrap()]).output().expect("spawn qumbra-node check")
}

/// `check` accepts the box producer's V6 config, names the V6 hash and the
/// 21 held keys — and still refuses a wrong pin, including the L1 base's hash
/// (the V6 hash is the one a V6 node pins).
#[test]
fn check_accepts_a_v6_config_and_still_refuses_a_wrong_pin() {
    let dir = tmp("ok");
    let hash = init_v6(&dir);
    let out = check(&producer_config(&dir, &hash));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "check refused the V6 config: {stdout} {stderr}");
    assert!(stdout.contains("qumbra-node check: OK"), "{stdout}");
    assert!(stdout.contains(&format!("genesis hash: {hash}")), "the V6 hash is reported: {stdout}");
    assert!(stdout.contains("keys held:    21"), "{stdout}");

    let wrong = check(&producer_config(&dir, &"00".repeat(32)));
    assert!(!wrong.status.success(), "a wrong pin must fail check");
    let why = String::from_utf8_lossy(&wrong.stderr);
    assert!(why.contains(&format!("!= expected {} — refusing to start", "00".repeat(32))), "{why}");

    let gen = std::fs::read(dir.join("genesis.qmb")).unwrap();
    let qumbra_node::annulet_genesis::AnyGenesis::V6(v6) = qumbra_node::annulet_genesis::load_any(&gen).unwrap() else {
        panic!("init --t2 writes a V6 genesis")
    };
    assert_eq!(v6.hash_hex(), hash);
    let base = check(&producer_config(&dir, &v6.base.hash_hex()));
    assert!(!base.status.success(), "the L1 base's hash is not a V6 node's pin");
    let _ = std::fs::remove_dir_all(&dir);
}
