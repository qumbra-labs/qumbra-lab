//! Issue #180 acceptance: the **block-log replay path** on a real `qumbra-node`
//! process, a real data directory, and a snapshot that is **provably behind the
//! tip**.
//!
//! ## Why this test exists
//!
//! `run_until` flushes `snapshot.bin` at the tip on the way out, so *every*
//! graceful restart resumes with nothing left to replay and prints
//! `replayed 0 records`. Two hosts rolled onto `t0-wan-4` on 2026-08-01 both
//! printed `<N>=0` — node3 because its log held only genesis, node0 because its
//! SIGTERM flush had already caught the snapshot up — and the two readings were
//! textually identical. The path is therefore dead code on every planned
//! restart, and live on exactly one occasion: an **ungraceful** stop (SIGKILL,
//! OOM, power loss, a host wedged past `stop_grace_period`). That is when
//! recovery matters most and it is the one case never demonstrated.
//!
//! `Node::open` replays log records past the snapshot and is unit-tested
//! (`open_equals_replay_on_the_finalized_checkpoint_and_state`,
//! `a_finalization_recorded_after_the_snapshot_still_survives`), and issue #162
//! added `rewind_to` on the same path via `apply_logged_block`. **All of that is
//! in-process.** What was never claimed is that it works on a data dir that a
//! killed process left behind, and that is the only thing this file adds.
//!
//! ## What it proves, and what it does not
//!
//! It is a **rig** result, not a host result. It does not touch, and must never
//! touch, a live T0 host: `docker kill` on a soaking net is a separate decision
//! and costs that container's graceful-shutdown property. The production
//! observation stays owed and comes free the next time a host stops ungracefully
//! for its own reasons.
//!
//! Not covered here (stated rather than implied): a **finalization** record in
//! the replayed tail. The checkpoint cadence is 8 blocks, so reaching a second
//! cadence slot would cost ~10 further minutes of wall clock on the shared rig;
//! the in-process `a_finalization_recorded_after_the_snapshot_still_survives`
//! covers that case and this test's tail is blocks only. The finalized head and
//! its identity are still asserted to survive the kill — they arrive via the
//! snapshot rather than via the tail.
//!
//! ## Cost, and why it is what it is
//!
//! `mine_interval` is the genesis file's FROZEN `block_time_secs` (75 s) and the
//! binary exposes no override, so three blocks of chain cost ~225 s of wall clock
//! plus three process starts. A `--mine-interval-secs` flag would make this test
//! seconds long; it was **deliberately not added**, because the block-production
//! cadence is consensus-adjacent and a knob on the shipping binary that exists
//! only to make a test cheap is exactly the scope growth the lab's discipline
//! warns about. See the PR body.
//!
//! Unix-only: the whole point is a POSIX `SIGKILL`, which a process cannot
//! handle, cannot flush through, and cannot fake.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use qlab_node::{ChainStore as _, MemNode, NodeState as _};
use qumbra_node::genesis::GenesisFile;

/// How long to wait for the child to print "qumbra-node running" after spawn.
/// RandomX light-mode init is the long pole and is silent on stdout.
const START_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for a graceful exit after SIGTERM.
const STOP_TIMEOUT: Duration = Duration::from_secs(60);
/// How long to wait for one mined block. The nominal figure is the genesis
/// file's FROZEN `block_time_secs` (75 s); the slack absorbs PoW variance and a
/// rig running other work.
const BLOCK_TIMEOUT: Duration = Duration::from_secs(240);
/// Telemetry cadence for the child — OBSERVABILITY ONLY (the flag's own
/// contract). It is how this test reads `tip=` without an RPC, and one line a
/// second keeps the kill within a second of the height it was aimed at.
const SAMPLE_SECS: &str = "1";
/// The LAST line of the startup banner. `qumbra-node running` is the FIRST, and
/// the `RECOVERY` line sits between them — so waiting on the first would race
/// the very line this test reads.
const BANNER_END: &str = "(SIGINT/SIGTERM/SIGHUP to shut down";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

/// `genesis init` + a one-node config in `base`. Returns the config path.
///
/// `mining = true` and `dial_peers = []` is the combination issue #106's gate
/// reads as `MineGate::Alone` — no address in the book and no live peer means
/// this node IS the net — so it extends its own chain from genesis, which is
/// what gives this test a tip to get ahead of the snapshot.
fn stage_node(base: &Path) -> PathBuf {
    let _ = std::fs::remove_dir_all(base);
    std::fs::create_dir_all(base).expect("create staging dir");

    let status = Command::new(bin())
        .args(["genesis", "init", "--out"])
        .arg(base)
        .status()
        .expect("spawn genesis init");
    assert!(status.success(), "genesis init must succeed: {status}");

    let data_dir = base.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    let keys_dir = base.join("keys");
    let mut key_paths: Vec<String> = std::fs::read_dir(&keys_dir)
        .expect("keys dir")
        .map(|e| e.unwrap().path().display().to_string())
        .collect();
    key_paths.sort();
    assert_eq!(key_paths.len(), 21, "genesis init writes 21 committee keys");

    let keys_toml = key_paths
        .iter()
        .map(|p| format!("  \"{p}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let cfg = format!(
        r#"
data_dir = "{data}"
listen_addr = "127.0.0.1:0"
dial_peers = []
genesis_file = "{genesis}"
committee_key_paths = [
{keys}
]
mining = true
# Issue #411: discovery_addr defaults to the FIXED loopback port 9420, so any
# other qumbra-node alive on this machine — a leaked child of an aborted run, a
# dev node — makes this child exit at startup with EADDRINUSE on stderr, which
# a stdout needle-wait then misreads as a silent hang. This test never reads
# /v1/compact, so it opts out of the binary's one fixed-port default.
discovery_addr = "off"
"#,
        data = data_dir.display(),
        genesis = base.join("genesis.qmb").display(),
        keys = keys_toml,
    );
    let cfg_path = base.join("node.toml");
    std::fs::write(&cfg_path, cfg).unwrap();
    cfg_path
}

/// A spawned node that is KILLED WHEN DROPPED, so a panicking wait cannot leak
/// a live mining node. Before this guard, any timed-out wait below left the
/// child running forever — burning CPU and, before `discovery_addr = "off"`
/// above, holding port 9420 so that every later run of this test failed at
/// startup: issue #411's self-sustaining state.
struct NodeProc(Child);

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl std::ops::Deref for NodeProc {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for NodeProc {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

/// Spawn the real binary with the **default (real M3) tx verifier** — no
/// `--rehearsal-verifier`. A T0 chain mines coinbase-only blocks so the verifier
/// is never called, and running the default keeps this test on the production
/// startup path rather than beside it.
fn spawn_node(cfg_path: &Path) -> NodeProc {
    NodeProc(
        Command::new(bin())
            .args([
                "run",
                "--config",
                cfg_path.to_str().unwrap(),
                "--sample-interval-secs",
                SAMPLE_SECS,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn qumbra-node"),
    )
}

/// Drain a child pipe on a background thread into a shared buffer, so the test
/// thread can poll for a needle without blocking, and so a long run cannot fill
/// the pipe and stall the node.
fn start_drain<R: std::io::Read + Send + 'static>(pipe: R) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let buf_t = Arc::clone(&buf);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(pipe);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => buf_t.lock().unwrap().push_str(&line),
                Err(_) => break,
            }
        }
    });
    buf
}

/// Wait for `needle` in a pipe buffer AFTER the child is known to have exited
/// (the post-SIGTERM "shutdown complete" read). For a wait on a child that must
/// still be alive, use [`wait_for_needle_live`].
fn wait_for_needle(buf: &Mutex<String>, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if buf.lock().unwrap().contains(needle) {
            return;
        }
        if Instant::now() > deadline {
            let captured = buf.lock().unwrap().clone();
            panic!("timed out waiting for `{needle}` in child stdout; captured so far:\n{captured}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait for `needle` in the child's stdout, panicking IMMEDIATELY — with both
/// pipes' contents — if the child exits first. A dead child can never print the
/// needle, so burning the full timeout on one is pure disguise: issue #411
/// spent two days as a "macOS hang" that was really an instant
/// `Address already in use` exit, stated the whole time on a stderr that no
/// panic message ever showed.
fn wait_for_needle_live(
    child: &mut Child,
    out: &Mutex<String>,
    err: &Mutex<String>,
    needle: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        if out.lock().unwrap().contains(needle) {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            // A beat for the drain threads to flush what the child last wrote.
            std::thread::sleep(Duration::from_millis(200));
            if out.lock().unwrap().contains(needle) {
                return;
            }
            let stdout = out.lock().unwrap().clone();
            let stderr = err.lock().unwrap().clone();
            panic!(
                "child exited ({status}) before printing `{needle}`;\n\
                 --- captured stdout:\n{stdout}\n--- captured stderr:\n{stderr}"
            );
        }
        if Instant::now() > deadline {
            let stdout = out.lock().unwrap().clone();
            let stderr = err.lock().unwrap().clone();
            panic!(
                "timed out waiting for `{needle}` in child stdout (child still running);\n\
                 --- captured stdout:\n{stdout}\n--- captured stderr:\n{stderr}"
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait until the node's own telemetry says it is at `height`. `tip=` is the
/// first field on the line, so the trailing space makes `tip=3` unambiguous
/// against `tip=30`.
fn wait_for_tip(
    child: &mut Child,
    out: &Mutex<String>,
    err: &Mutex<String>,
    height: u64,
    timeout: Duration,
) {
    wait_for_needle_live(child, out, err, &format!("TELEMETRY tip={height} "), timeout);
}

fn signal(pid: u32, sig: &str) {
    let status = Command::new("kill")
        .args([sig, &pid.to_string()])
        .status()
        .unwrap_or_else(|e| panic!("send {sig}: {e}"));
    assert!(status.success(), "kill {sig} {pid} failed: {status}");
}

fn wait_exit(child: &mut Child, timeout: Duration, what: &str) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s,
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not exit within {timeout:?} after {what}");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("try_wait failed: {e}"),
        }
    }
}

fn snapshot_bytes(data_dir: &Path) -> Vec<u8> {
    std::fs::read(data_dir.join(qlab_node::SNAPSHOT)).expect("snapshot.bin on disk")
}

fn snapshot_height(bytes: &[u8]) -> u64 {
    let snap: qlab_node::Snapshot = bincode::deserialize(bytes).expect("snapshot.bin decodes");
    assert_eq!(
        snap.format_version,
        qlab_node::FORMAT_VERSION,
        "snapshot written at the current on-disk format version"
    );
    snap.applied_height
}

/// ACCEPTANCE (issue #180). Three real processes on one data dir:
///
/// 1. run → mine → **SIGTERM**, which flushes `snapshot.bin` at the tip;
/// 2. restart → mine two more blocks → **SIGKILL**, so the snapshot stays where
///    (1) left it while the append-only log runs ahead of it;
/// 3. restart → the `RECOVERY` line must report a snapshot **below** the tip and
///    `replayed <N> records` with `<N> > 0`.
///
/// Between (2) and (3) the data dir is opened in-process twice — snapshot-assisted
/// (`open`) and from-genesis (`replay`) — and the two must agree on tip,
/// commitment root, nullifier set, finalized head **and the checkpoint identity**.
/// `<N> > 0` alone would only prove records were counted.
#[test]
fn a_sigkilled_node_replays_the_log_past_a_stale_snapshot() {
    let base = std::env::temp_dir().join(format!(
        "qmb-i180-sigkill-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let cfg_path = stage_node(&base);
    let data_dir = base.join("data");
    let genesis = GenesisFile::load(base.join("genesis.qmb")).expect("genesis file loads");

    // ---- (1) a clean run and a GRACEFUL stop: the snapshot lands at the tip ----
    let mut child = spawn_node(&cfg_path);
    let pid = child.id();
    let out = start_drain(child.stdout.take().expect("stdout piped"));
    let err = start_drain(child.stderr.take().expect("stderr piped"));

    wait_for_needle_live(&mut child, &out, &err, BANNER_END, START_TIMEOUT);
    wait_for_tip(&mut child, &out, &err, 1, BLOCK_TIMEOUT);
    signal(pid, "-TERM");
    let status = wait_exit(&mut child, STOP_TIMEOUT, "SIGTERM");
    assert!(status.success(), "graceful stop must exit 0; got {status}");
    wait_for_needle(&out, "shutdown complete (snapshot flushed)", Duration::from_secs(5));

    let snap_at_flush = snapshot_bytes(&data_dir);
    let snap_height = snapshot_height(&snap_at_flush);
    assert!(
        snap_height >= 1,
        "the graceful flush must snapshot a mined chain, not just genesis (got height {snap_height})"
    );

    // ---- (2) advance past that snapshot, then die UNGRACEFULLY ----------------
    //
    // Two more blocks, not one: a replay that applies the first tail record and
    // stops would satisfy `<N> > 0` and still be broken.
    let target_tip = snap_height + 2;
    let mut child = spawn_node(&cfg_path);
    let pid = child.id();
    let out2 = start_drain(child.stdout.take().expect("stdout piped"));
    let err2 = start_drain(child.stderr.take().expect("stderr piped"));

    wait_for_needle_live(&mut child, &out2, &err2, BANNER_END, START_TIMEOUT);
    // The CONTROL. This restart followed a graceful stop, so it is exactly the
    // reading issue #180 is about: a snapshot at the tip and nothing left to
    // replay. If this line ever stops being `0`, the contrast the test draws is
    // gone and the `> 0` below proves nothing.
    let clean_restart = format!(
        "RECOVERY restored snapshot at height {snap_height}, replayed 0 records, \
         resumed at tip {snap_height}"
    );
    let banner2 = out2.lock().unwrap().clone();
    assert!(
        banner2.contains(&clean_restart),
        "a restart after a graceful stop must replay nothing (`{clean_restart}`); stdout:\n{banner2}"
    );
    wait_for_tip(&mut child, &out2, &err2, target_tip, BLOCK_TIMEOUT * 2);

    // SIGKILL: uncatchable, so no handler runs, no flush is attempted, and the
    // snapshot on disk is exactly the one the graceful stop in (1) wrote.
    signal(pid, "-KILL");
    let status = wait_exit(&mut child, STOP_TIMEOUT, "SIGKILL");
    assert_eq!(
        status.signal(),
        Some(9),
        "the node must have died to SIGKILL, not exited on its own; got {status}"
    );
    assert_eq!(status.code(), None, "a signalled death has no exit code; got {status}");
    let captured2 = out2.lock().unwrap().clone();
    assert!(
        !captured2.contains("shutdown complete"),
        "no graceful-shutdown line may appear after SIGKILL; stdout:\n{captured2}"
    );

    // ---- the snapshot is PROVABLY stale --------------------------------------
    let snap_after_kill = snapshot_bytes(&data_dir);
    assert_eq!(
        snap_after_kill, snap_at_flush,
        "SIGKILL wrote nothing: snapshot.bin is byte-identical to the one the graceful stop left"
    );
    assert_eq!(snapshot_height(&snap_after_kill), snap_height);

    // ---- what the log actually replays to ------------------------------------
    let opened = MemNode::open(&data_dir, genesis.genesis_block.clone()).expect("open the killed data dir");
    let report = opened.recovery_report().clone();
    assert_eq!(
        report.snapshot_height,
        Some(snap_height),
        "recovery resumed from the stale snapshot, not from a fresh start"
    );
    assert!(
        report.resumed_tip > snap_height,
        "THE PROPERTY: the snapshot ({snap_height}) is strictly below the tip ({}) — \
         a clean-shutdown restart structurally cannot produce this",
        report.resumed_tip
    );
    assert!(
        report.resumed_tip >= target_tip,
        "expected at least tip {target_tip}, got {}",
        report.resumed_tip
    );
    assert!(report.replayed_records > 0, "the log tail must have been replayed");
    // Every record above the snapshot in this window is a block (the next
    // checkpoint cadence slot is far above this tip), so the count is exactly the
    // height difference — a stronger statement than `> 0`.
    assert_eq!(
        report.replayed_records as u64,
        report.resumed_tip - snap_height,
        "every block above the snapshot was replayed, and nothing else was counted"
    );

    // ---- the replayed state is RIGHT, not merely present ---------------------
    //
    // The comparison `open_equals_replay_on_the_finalized_checkpoint_and_state`
    // makes in-process, made here against a data dir a killed process left.
    let replayed = MemNode::replay(&data_dir, genesis.genesis_block.clone()).expect("from-genesis replay");
    assert_eq!(opened.tip_hash(), replayed.tip_hash(), "same tip as a full genesis replay");
    assert_eq!(opened.commitment_count(), replayed.commitment_count());
    assert_eq!(opened.commitment_root(), replayed.commitment_root(), "same commitment root");
    assert_eq!(opened.nullifier_count(), replayed.nullifier_count());
    assert_eq!(opened.finalized_height(), replayed.finalized_height());
    assert_eq!(
        opened.restored_checkpoint(),
        replayed.restored_checkpoint(),
        "open == replay on the exact checkpoint, including the identity-bearing hash"
    );
    // A height without an identity is half an answer (PR #171 / issue #84).
    assert!(
        opened.restored_checkpoint().is_some(),
        "the finalized checkpoint and its identity survive the kill"
    );
    assert_eq!(
        opened.finalized_height(),
        Some(0),
        "genesis was finalized before the snapshot and is still the finalized head"
    );
    // The block-level comparison is what actually carries the "state is right"
    // claim at this height. **The commitment-tree equality above is vacuous
    // here**: issue #102 appends the coinbase leaf a block MATURES — the one
    // minted `COINBASE_MATURITY_BLOCKS` back — not its own, so at a tip of 3 the
    // tree is still empty on both sides and would compare equal even if the tail
    // had never been applied. Headers chain by `prev`, so agreeing on the tip
    // hash is agreeing on the whole applied prefix.
    let tip_block = opened.chain().block(&opened.tip_hash()).expect("tip block is stored");
    assert_eq!(
        tip_block.header.height, report.resumed_tip,
        "the stored tip block is the one the tail replayed to"
    );
    assert_eq!(
        Some(tip_block),
        replayed.chain().block(&replayed.tip_hash()),
        "the replayed tip block is field-for-field identical to the from-genesis one"
    );

    // ---- (3) the real binary's own RECOVERY line -----------------------------
    let expected = format!(
        "RECOVERY restored snapshot at height {snap_height}, replayed {} records, resumed at tip {}",
        report.replayed_records, report.resumed_tip
    );
    let mut child = spawn_node(&cfg_path);
    let pid = child.id();
    let out3 = start_drain(child.stdout.take().expect("stdout piped"));
    let err3 = start_drain(child.stderr.take().expect("stderr piped"));
    wait_for_needle_live(&mut child, &out3, &err3, BANNER_END, START_TIMEOUT);
    let captured3 = out3.lock().unwrap().clone();
    assert!(
        captured3.contains(&expected),
        "the restarted binary must print `{expected}`; stdout:\n{captured3}"
    );

    signal(pid, "-TERM");
    let _ = wait_exit(&mut child, STOP_TIMEOUT, "SIGTERM");

    let _ = std::fs::remove_dir_all(&base);
}
