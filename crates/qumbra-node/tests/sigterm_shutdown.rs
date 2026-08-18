//! Issue #145 acceptance: a **real SIGTERM** delivered to a real `qumbra-node`
//! process must reach the graceful-shutdown path and leave `snapshot.bin` and
//! `peers.dat` on disk.
//!
//! The in-crate `run_until_flushes_a_snapshot_on_shutdown` test only proves that
//! a pre-set `AtomicBool` drives the flush — it says nothing about whether
//! SIGTERM ever sets that flag. This test is the signal witness: spawn the
//! binary, `kill -TERM`, wait for a clean exit, assert both files exist and the
//! status line is honest.
//!
//! Unix-only: the defect is specifically about POSIX SIGTERM (Docker/systemd).
//!
//! ⚠️ The second half of that sentence used to read "Windows maps ctrlc's
//! termination feature differently and is not a T0 deploy target", and lab #478
//! made half of it wrong: Windows IS a supported joiner/miner platform now (it is
//! still not a T0 *fleet* host, and that part stands). The accurate statement is
//! that Windows has no SIGTERM at all — its stop events are console control
//! events, `ctrlc` is not used there, and the mechanism plus what is and is not
//! tested about it lives in `qumbra_node::shutdown`. This file stays unix-only
//! because SIGTERM stays unix-only, not because Windows is out of scope.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long to wait for the child to print "qumbra-node running" after spawn.
/// RandomX light-mode init is the long pole and is silent on stdout.
const START_TIMEOUT: Duration = Duration::from_secs(120);
/// How long to wait for a graceful exit after SIGTERM.
const STOP_TIMEOUT: Duration = Duration::from_secs(60);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

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

    // mining = false: we only need the process to arm its signal handler and
    // enter the loop. A real RandomX mine is irrelevant to the shutdown path.
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
mining = false
# Issue #411: opt out of the fixed default discovery port (127.0.0.1:9420) so a
# stray node elsewhere on the machine cannot make this child exit at startup —
# see sigkill_replay.rs's staged config for the full story.
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

fn spawn_node(cfg_path: &Path) -> Child {
    Command::new(bin())
        .args([
            "run",
            "--config",
            cfg_path.to_str().unwrap(),
            "--rehearsal-verifier",
            "--sample-interval-secs",
            "3600",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qumbra-node")
}

/// Drain `stdout` on a background thread into a shared buffer so the test thread
/// can poll for a needle without blocking past its deadline on a silent process
/// (RandomX init prints nothing until the banner).
fn start_stdout_drain(stdout: std::process::ChildStdout) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let buf_t = Arc::clone(&buf);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
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

fn wait_for_needle(buf: &Mutex<String>, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        {
            let captured = buf.lock().unwrap();
            if captured.contains(needle) {
                return;
            }
        }
        if Instant::now() > deadline {
            let captured = buf.lock().unwrap().clone();
            panic!(
                "timed out waiting for `{needle}` in child stdout; captured so far:\n{captured}"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Startup wait with the child's liveness checked — the same failure-mode fix
/// as `sigkill_replay.rs`'s `wait_for_needle_live` (issue #411): a child that
/// exits before printing the needle panics NOW, with its stderr, instead of
/// burning the full timeout on a process that can never print it.
fn wait_for_startup(child: &mut Child, buf: &Mutex<String>, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if buf.lock().unwrap().contains(needle) {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            // A beat for the drain thread to flush what the child last wrote.
            std::thread::sleep(Duration::from_millis(200));
            if buf.lock().unwrap().contains(needle) {
                return;
            }
            let mut stderr = String::new();
            if let Some(mut err) = child.stderr.take() {
                let _ = err.read_to_string(&mut stderr);
            }
            let stdout = buf.lock().unwrap().clone();
            panic!(
                "child exited ({status}) before printing `{needle}`;\n\
                 --- captured stdout:\n{stdout}\n--- captured stderr:\n{stderr}"
            );
        }
        if Instant::now() > deadline {
            let captured = buf.lock().unwrap().clone();
            panic!(
                "timed out waiting for `{needle}` in child stdout (child still running); \
                 captured so far:\n{captured}"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn send_sigterm(pid: u32) {
    let kill_status = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(
        kill_status.success(),
        "kill -TERM {pid} failed: {kill_status}"
    );
}

fn wait_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s,
            Ok(None) if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not exit within {timeout:?} after SIGTERM");
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("try_wait failed: {e}"),
        }
    }
}

fn snapshot_of(buf: &Mutex<String>) -> String {
    buf.lock().unwrap().clone()
}

#[test]
fn sigterm_flushes_snapshot_and_peers_dat() {
    let base = std::env::temp_dir().join(format!(
        "qmb-i145-sigterm-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let cfg_path = stage_node(&base);
    let data_dir = base.join("data");

    let mut child = spawn_node(&cfg_path);
    let pid = child.id();
    let stdout = child.stdout.take().expect("stdout piped");
    let buf = start_stdout_drain(stdout);

    wait_for_startup(&mut child, &buf, "qumbra-node running", START_TIMEOUT);

    // Real SIGTERM — the same signal Docker `compose stop` and `systemctl stop`
    // send. This is the whole point of the test; a pre-set AtomicBool is not it.
    send_sigterm(pid);
    let status = wait_exit(&mut child, STOP_TIMEOUT);
    // Give the drain thread a beat to finish reading the shutdown lines.
    wait_for_needle(&buf, "shutdown complete", Duration::from_secs(5));
    let captured = snapshot_of(&buf);

    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }

    assert!(
        status.success(),
        "node must exit 0 after graceful SIGTERM; status={status}, stderr:\n{stderr}\nstdout:\n{captured}"
    );
    assert!(
        captured.contains("shutdown complete (snapshot flushed)"),
        "success line after a real SIGTERM flush; stdout:\n{captured}\nstderr:\n{stderr}"
    );

    let snapshot = data_dir.join(qlab_node::SNAPSHOT);
    let peers = data_dir.join("peers.dat");
    assert!(
        snapshot.exists(),
        "SIGTERM must flush snapshot.bin; missing at {}; stderr:\n{stderr}",
        snapshot.display()
    );
    assert!(
        peers.exists(),
        "SIGTERM must write peers.dat on the same path; missing at {}; stderr:\n{stderr}",
        peers.display()
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// When the flush fails, the process must not claim success. Force a flush
/// failure by making the data dir read-only after the node has started, then
/// SIGTERM and check the status line on stdout.
#[test]
fn sigterm_does_not_claim_flush_when_it_failed() {
    let base = std::env::temp_dir().join(format!(
        "qmb-i145-sigterm-fail-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let cfg_path = stage_node(&base);
    let data_dir = base.join("data");

    let mut child = spawn_node(&cfg_path);
    let pid = child.id();
    let stdout = child.stdout.take().expect("stdout piped");
    let buf = start_stdout_drain(stdout);

    wait_for_startup(&mut child, &buf, "qumbra-node running", START_TIMEOUT);

    // Freeze the data dir so the atomic snapshot write cannot create its tmp file.
    let mut perms = std::fs::metadata(&data_dir).unwrap().permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&data_dir, perms.clone()).unwrap();

    send_sigterm(pid);
    let _status = wait_exit(&mut child, STOP_TIMEOUT);
    wait_for_needle(&buf, "shutdown complete", Duration::from_secs(5));
    let captured = snapshot_of(&buf);

    assert!(
        captured.contains("shutdown complete (snapshot flush failed)"),
        "must report flush failure, not claim success; stdout:\n{captured}"
    );
    assert!(
        !captured.contains("shutdown complete (snapshot flushed)"),
        "success line must be absent on flush failure; stdout:\n{captured}"
    );

    perms.set_readonly(false);
    let _ = std::fs::set_permissions(&data_dir, perms);
    let _ = std::fs::remove_dir_all(&base);
}
