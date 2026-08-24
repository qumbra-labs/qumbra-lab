//! Lab #552(a) — **`qumbra-node` refuses to mine without a payout key, proven
//! through the REAL binary.**
//!
//! T2 blocks 607, 610 and 611 minted about 15 QMB to
//! `qlab_p2p::adapter::UNCONFIGURED_MINER_RKM` — a fixed constant nobody holds a
//! spend key for, whose lane-major LE encoding is `0111011101110111…`. The value
//! was documented, and `qumbra-node` warned about it loudly at startup, and it
//! still happened. **That is the finding: the warning was at startup and the burn
//! was at every block, and nobody rereads startup logs.**
//!
//! So the severity changed, on the binary's two operator surfaces:
//!
//! * `qumbra-node run` refuses, before it reads the genesis file;
//! * `qumbra-node check` refuses the same combination, so a pre-flight cannot
//!   tell an operator a config is fine while `run` is about to reject it (lab
//!   #475 is the recorded cost of finding a payout mistake one host at a time).
//!
//! `RunningNode::start` — the library seam the in-process rehearsals use — keeps
//! the warning verbatim; `run.rs`'s
//! `the_library_seam_still_mines_without_a_payout_key_and_only_warns` is that
//! boundary's assertion. `qlab-p2p` is untouched.
//!
//! **Why the binary and not a seam.** The gate reads nothing but the config, so a
//! unit test can prove the predicate (`run.rs`'s
//! `mining_with_no_miner_rkm_is_refused_and_the_refusal_names_miner_rkm`) — but
//! it cannot prove that the binary *applies* it, which is the entire defect. A
//! gate nothing calls is exactly the shape of the warning it replaces.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

/// A real devnet genesis + its 21 committee key files in a fresh temp dir, built
/// by `genesis init` — the binary's own path, so the fixture cannot drift from
/// what an operator gets.
fn staged(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!("qmb_i552_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).expect("temp dir");
    let status = Command::new(bin())
        .args(["genesis", "init", "--out"])
        .arg(&base)
        .status()
        .expect("spawn genesis init");
    assert!(status.success(), "genesis init must succeed: {status}");
    std::fs::create_dir_all(base.join("data")).expect("data dir");
    base
}

/// A one-node config in `base` with the two mining fields the caller chose.
///
/// `committee_key_paths` is empty and `discovery_addr = "off"`: neither is what
/// these tests are about, and the fixed default discovery port would make a
/// second `qumbra-node` alive on this machine fail the bind (issue #411). Paths go
/// in TOML *literal* strings — a Windows temp path is nothing but backslashes and
/// a basic string would treat them as escapes (the lab #478 finding).
fn config(base: &Path, body: &str) -> PathBuf {
    let cfg = base.join("node.toml");
    std::fs::write(
        &cfg,
        format!(
            "data_dir = '{data}'\n\
             listen_addr = \"127.0.0.1:0\"\n\
             dial_peers = []\n\
             genesis_file = '{genesis}'\n\
             committee_key_paths = []\n\
             discovery_addr = \"off\"\n\
             {body}",
            data = base.join("data").display(),
            genesis = base.join("genesis.qmb").display(),
        ),
    )
    .expect("write config");
    cfg
}

fn invoke(cmd: &str, cfg: &Path) -> Output {
    Command::new(bin())
        .args([cmd, "--config"])
        .arg(cfg)
        .output()
        .unwrap_or_else(|e| panic!("spawn qumbra-node {cmd}: {e}"))
}

/// Both streams, because the two commands do not agree on where they speak:
/// `check` prints its report on stdout, and `main`'s error handler writes the
/// refusal to stderr. A test that read only one would pass for the wrong reason.
fn both_streams(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The four things the refusal has to say, asserted together because each one
/// alone would let a weaker message through: the field to add, the setting that
/// triggered it, what the consequence would have been, and the other way out.
fn assert_names_the_missing_thing(text: &str) {
    assert!(text.contains("miner_rkm"), "must name the missing field: {text}");
    assert!(text.contains("mining = true"), "must name the setting: {text}");
    assert!(text.contains("BURNED"), "must say what would happen: {text}");
    assert!(text.contains("`mining = false`"), "must name the other exit: {text}");
}

/// How long `run` gets to refuse before this test gives up and kills it.
///
/// 🔴 **Why this is not `Command::output()`.** `qumbra-node run` does not return —
/// it mines until it is signalled. So if the gate ever stops firing, an
/// `output()` here would not fail, it would **hang the suite** while a real
/// RandomX miner burns a CI core. The timeout converts that regression into a
/// named failure, and the kill is what stops the node. Generous on purpose: the
/// refusal is a config predicate applied before the ~256 MiB RandomX cache, so a
/// healthy run exits in well under a second and only a broken one comes near
/// this bound.
const REFUSAL_DEADLINE: Duration = Duration::from_secs(60);

/// Spawn `qumbra-node run`, wait for it to refuse, and kill it if it does not.
///
/// Returns the exit status and both streams. Output is read only after the child
/// is done, which is safe here for the same reason the deadline is generous: a
/// refusing node writes two lines, nowhere near a pipe buffer. A node that
/// wrongly STARTED could fill a pipe and stall — and stalling is precisely what
/// the deadline below turns into a test failure rather than a hung suite.
fn run_until_it_refuses(cfg: &Path) -> (bool, String) {
    let mut child = Command::new(bin())
        .args(["run", "--config"])
        .arg(cfg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qumbra-node run");

    let deadline = Instant::now() + REFUSAL_DEADLINE;
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    let mut text = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut text);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut text);
    }
    match status {
        Some(s) => (s.success(), text),
        None => panic!(
            "`qumbra-node run` did not exit within {REFUSAL_DEADLINE:?} — it STARTED on a config \
             with `mining = true` and no `miner_rkm`, which is the whole defect this test is \
             about (killed it). Output so far: {text}"
        ),
    }
}

/// **ACCEPTANCE — `run` REFUSES, and it refuses before it reads the genesis.**
///
/// This is the defect: T2 blocks 607, 610 and 611 were mined by a node in exactly
/// this configuration, which warned and mined anyway.
///
/// The ordering half is not decoration. `run_node` applies this gate as its first
/// act after the config loads, ahead of the genesis read and ahead of the
/// ~256 MiB RandomX cache, so a node with nobody to pay is told so at the
/// cheapest possible moment. The **absence** of lab #300's
/// `STARTUP loading genesis file` line is what proves that placement from outside
/// the process — if the gate is ever moved down into `prepare`, that line appears
/// and this assertion fails by name.
#[test]
fn run_refuses_mining_with_no_miner_rkm_before_it_reads_the_genesis() {
    let base = staged("run_refuse");
    let cfg = config(&base, "mining = true\n");

    let (started, text) = run_until_it_refuses(&cfg);
    let _ = std::fs::remove_dir_all(&base);

    assert!(!started, "the node must not start: {text}");
    assert_names_the_missing_thing(&text);
    assert!(
        !text.contains("STARTUP loading genesis file"),
        "the payout gate must refuse BEFORE the genesis read: {text}"
    );
    // Lab #300's entry line still comes first — the refusal is after the
    // announce, not instead of it, so a refusing node is still distinguishable
    // from one that died before it could say anything.
    assert!(
        text.contains("qumbra-node starting"),
        "the entry line still precedes everything: {text}"
    );
}

/// **ACCEPTANCE — `check` refuses whatever `run` refuses.**
///
/// `check_config`'s own comment is the requirement: a pre-flight that skips a
/// refusal "would tell an operator a swap is safe when startup is about to refuse
/// it". Before this change `check` printed
/// `miner_rkm: ⚠️ UNSET with mining = true` and exited 0, which is the same
/// mistake as the startup warning one layer earlier.
#[test]
fn check_refuses_mining_with_no_miner_rkm_instead_of_reporting_it_ok() {
    let base = staged("check_refuse");
    let cfg = config(&base, "mining = true\n");

    let out = invoke("check", &cfg);
    let text = both_streams(&out);
    let _ = std::fs::remove_dir_all(&base);

    assert!(!out.status.success(), "check must exit non-zero: {text}");
    assert_names_the_missing_thing(&text);
    assert!(!text.contains("check: OK"), "and must NOT report OK: {text}");
    assert!(
        !text.contains("UNSET with mining = true"),
        "the old warn line is gone, not printed alongside a failure: {text}"
    );
}

/// **REGRESSION GUARD — `mining = false` with no `miner_rkm` still passes.**
///
/// This is the ordinary node: every explorer observer, `tests/sigterm_shutdown.rs`,
/// and three of the four hosts in `deploy/hosts.example`. It is the regression this
/// change was most likely to introduce, so it is asserted through the binary and
/// not only through the predicate — a gate wired in at the wrong place would refuse
/// here too.
#[test]
fn check_still_accepts_a_non_mining_node_with_no_miner_rkm() {
    let base = staged("check_nonmining");
    let cfg = config(&base, "mining = false\n");

    let out = invoke("check", &cfg);
    let text = both_streams(&out);
    let _ = std::fs::remove_dir_all(&base);

    assert!(out.status.success(), "a non-mining node is normal: {text}");
    assert!(text.contains("check: OK"), "{text}");
    assert!(text.contains("mining:       false"), "{text}");
    assert!(
        text.contains("not set (this node does not mine)"),
        "and the report says why the field is empty: {text}"
    );
}

/// **ACCEPTANCE — `mining = true` with a real key passes `check` and is echoed
/// back verbatim.**
///
/// The echo matters as much as the pass: lab #475's whole point is that an
/// operator can see, before starting a host, which key that host will pay. That
/// `run` then mines to this key is asserted in-process by `run.rs`'s
/// `a_mining_node_with_a_real_miner_rkm_starts_and_pays_its_coinbase_to_it`, which
/// reads the payee out of the height-1 body — a claim a `check` invocation cannot
/// make.
#[test]
fn check_accepts_mining_with_a_real_miner_rkm_and_echoes_it() {
    const RKM: &str = "0100000000000000020000000000000003000000000000000400000000000000";
    let base = staged("check_paying");
    let cfg = config(&base, &format!("mining = true\nminer_rkm = \"{RKM}\"\n"));

    let out = invoke("check", &cfg);
    let text = both_streams(&out);
    let _ = std::fs::remove_dir_all(&base);

    assert!(out.status.success(), "a configured miner is fine: {text}");
    assert!(text.contains("check: OK"), "{text}");
    assert!(text.contains("mining:       true"), "{text}");
    assert!(text.contains(RKM), "the payee is echoed for the operator to check: {text}");
}

/// A malformed `miner_rkm` is still a parse refusal rather than the payout
/// refusal, on both mining settings — lab #475's behaviour, unchanged. The two
/// messages are distinct on purpose: "you set this wrong" and "you did not set
/// this" call for different fixes, and the all-zero message used to end with
/// *"Omit the key to mine to the unconfigured burn address"*, which this change
/// makes false and which is corrected in `config.rs`.
#[test]
fn a_malformed_miner_rkm_is_still_a_parse_refusal_and_no_longer_offers_omission() {
    let base = staged("check_badrkm");
    let cfg = config(&base, &format!("mining = true\nminer_rkm = \"{}\"\n", "0".repeat(64)));

    let out = invoke("check", &cfg);
    let text = both_streams(&out);
    let _ = std::fs::remove_dir_all(&base);

    assert!(!out.status.success(), "an all-zero key is refused: {text}");
    assert!(text.contains("all zero"), "by name: {text}");
    assert!(
        !text.contains("Omit the key"),
        "and must no longer suggest omitting it, which the binary now refuses: {text}"
    );
}
