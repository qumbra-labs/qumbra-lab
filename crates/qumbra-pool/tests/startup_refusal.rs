//! Process-level locks for the first-service gate (lab #519).
//!
//! These use `check` / `run`, not the config helper directly: removing either
//! call-site must make CI red before a pool can bind or accept a miner.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

struct ConfigFile(PathBuf);

impl ConfigFile {
    fn new(contents: &str) -> Self {
        let serial = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "qumbra-pool-startup-refusal-{}-{serial}.toml",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write process-test config");
        Self(path)
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn invoke(command: &str, config: &str) -> Output {
    let file = ConfigFile::new(config);
    Command::new(env!("CARGO_BIN_EXE_qumbra-pool"))
        .args([command, "--config"])
        .arg(&file.0)
        .output()
        .expect("invoke qumbra-pool")
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn check_refuses_a_static_template_by_name() {
    let output = invoke(
        "check",
        r#"
listen_addr = "127.0.0.1:3333"
share_difficulty = 1024
payout_rkm = "0100000000000000020000000000000003000000000000000400000000000000"

[template]
form = "v5"
prev = "1111111111111111111111111111111111111111111111111111111111111111"
height = 100
timestamp = 1785000000
difficulty = 256
tx_body_commitment = "2222222222222222222222222222222222222222222222222222222222222222"
seed_hash = "3333333333333333333333333333333333333333333333333333333333333333"
"#,
    );
    assert!(
        !output.status.success(),
        "static service config must refuse"
    );
    let text = combined(&output);
    assert!(text.contains("static-template-source-refused"), "{text}");
    assert!(!text.contains("qumbra-pool check: ok"), "{text}");
}

#[test]
fn run_refuses_an_all_zero_payout_before_connect_or_bind() {
    let output = invoke(
        "run",
        r#"
listen_addr = "127.0.0.1:3333"
share_difficulty = 1024
node_rpc = "http://unreachable.invalid:9420"
payout_rkm = "0000000000000000000000000000000000000000000000000000000000000000"
"#,
    );
    assert!(!output.status.success(), "zero payout must refuse");
    let text = combined(&output);
    assert!(text.contains("all-zero-payout-rkm"), "{text}");
    assert!(
        !text.contains("node_rpc"),
        "the refusal must precede RPC: {text}"
    );
    assert!(
        !text.contains("listening on"),
        "the refusal must precede bind: {text}"
    );
}
