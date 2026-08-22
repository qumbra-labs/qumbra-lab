//! CLI exit-code lock for `qumbra-node audit-emission` (lab #299 / QUM-82).
//!
//! The library tests cover the arithmetic and report shape; this file only
//! asserts that the **binary** surfaces the three exit codes the operator
//! contract promises (0 clean / 1 mismatch / 2 cannot-run) without parsing
//! the text.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use qlab_devnet::body::{BlockBody, TxEntry, TxVerifier};
use qlab_devnet::header::BlockHeader;
use qlab_node::emission::coinbase;
use qlab_node::{genesis_block, ChainStore, MemNode, NodeState};
use qumbra_node::genesis::T0_GENESIS_DIFFICULTY;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    p.push(format!(
        "qumbra-audit-emission-cli-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

struct AcceptAll;
impl TxVerifier for AcceptAll {
    fn verify_tx(&self, _: &TxEntry) -> bool {
        true
    }
}

const RKM: [u64; 4] = [1, 2, 3, 4];

fn open_fresh(dir: &Path) -> MemNode {
    MemNode::open(dir, genesis_block(T0_GENESIS_DIFFICULTY, 0)).unwrap()
}

fn extend(node: &mut MemNode, committed_coinbase: u64) {
    let parent = node
        .chain()
        .block(&node.tip_hash())
        .expect("tip")
        .header();
    let height = parent.height + 1;
    let body = BlockBody::from_single_payee(vec![], committed_coinbase, RKM);
    let header = BlockHeader::child_of(&parent, height, T0_GENESIS_DIFFICULTY, body.commitment());
    node.apply_block(header, body, &AcceptAll).unwrap();
}

fn run_audit(dir: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["audit-emission", "--data-dir"];
    let dir_s = dir.to_str().unwrap();
    args.push(dir_s);
    args.extend_from_slice(extra);
    let out = Command::new(bin())
        .args(&args)
        .output()
        .expect("spawn qumbra-node audit-emission");
    let code = out.status.code().unwrap_or(255);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

#[test]
fn cli_clean_chain_exits_0() {
    let dir = temp_dir("clean");
    {
        let mut node = open_fresh(&dir);
        for h in 1..=4 {
            extend(&mut node, coinbase(h));
        }
    }
    let (code, stdout, stderr) = run_audit(&dir, &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("0 mismatches"), "stdout={stdout}");
    assert!(!stdout.contains("MISMATCH"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_mismatch_exits_1() {
    let dir = temp_dir("mismatch");
    {
        let mut node = open_fresh(&dir);
        for h in 1..=4 {
            let c = if h == 2 { coinbase(h + 1) } else { coinbase(h) };
            extend(&mut node, c);
        }
    }
    let (code, stdout, stderr) = run_audit(&dir, &[]);
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(stdout.contains("MISMATCH height=2"), "stdout={stdout}");
    assert!(stdout.contains("1 mismatch"), "stdout={stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_bad_dir_exits_2() {
    let missing = std::env::temp_dir().join(format!(
        "qumbra-audit-emission-cli-missing-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&missing);
    let (code, _stdout, stderr) = run_audit(&missing, &[]);
    assert_eq!(code, 2, "stderr={stderr}");
    assert!(stderr.contains("bad_dir") || stderr.contains("does not exist"), "stderr={stderr}");
}

#[test]
fn cli_interval_beyond_tip_exits_2() {
    let dir = temp_dir("beyond");
    {
        let mut node = open_fresh(&dir);
        extend(&mut node, coinbase(1));
    }
    let (code, _stdout, stderr) = run_audit(&dir, &["--from", "99"]);
    assert_eq!(code, 2, "stderr={stderr}");
    assert!(
        stderr.contains("interval_beyond_tip") || stderr.contains("beyond tip"),
        "stderr={stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_unreadable_log_exits_2() {
    // A non-empty blocks.log that does not decode is an unreadable_log refusal
    // from persist::read_records — MemNode::open surfaces it.
    let dir = temp_dir("garbage");
    std::fs::write(dir.join("blocks.log"), b"not a valid block log\x00\xff").unwrap();
    let (code, _stdout, stderr) = run_audit(&dir, &[]);
    assert_eq!(code, 2, "stderr={stderr}");
    assert!(
        stderr.contains("unreadable_log") || stderr.contains("could not open"),
        "stderr={stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cli_genesis_skip_exits_0() {
    let dir = temp_dir("genesis");
    {
        let mut node = open_fresh(&dir);
        extend(&mut node, coinbase(1));
    }
    let (code, stdout, stderr) = run_audit(&dir, &["--from", "0"]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("skipped genesis"), "stdout={stdout}");
    assert!(!stdout.contains("MISMATCH"), "stdout={stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
