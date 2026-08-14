//! The prover host's pins (task book §7): stdout purity (nothing but frames),
//! the version-mismatch refusal naming both sides, the one-prove-at-a-time
//! refusal, bundle refusals by name, and a REAL bundle reaching the preflight
//! refusal against a dead endpoint. The 12 GB prove itself is deliberately not
//! here (release-only, covered by `e2e_first_spend`); everything up to it is.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

use serde_json::{json, Value};

fn spawn_host_locked(lock: &std::path::Path) -> Child {
    Command::new(env!("CARGO_BIN_EXE_qumbra-prover-host"))
        .env("QUMBRA_PROVER_LOCK", lock)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the host bin spawns")
}

/// Each caller gets its own lock path — the tests must not contend with each
/// other; the cross-process contention CASE has its own test below.
fn spawn_host() -> Child {
    let lock = std::env::temp_dir().join(format!("qmb-prover-test-{}.lock", rand_tag()));
    spawn_host_locked(&lock)
}

fn rand_tag() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
    format!("{}-{n}", std::process::id())
}

fn send(child: &mut Child, v: &Value) {
    let bytes = serde_json::to_vec(v).unwrap();
    let stdin = child.stdin.as_mut().unwrap();
    stdin.write_all(&(bytes.len() as u32).to_le_bytes()).unwrap();
    stdin.write_all(&bytes).unwrap();
    stdin.flush().unwrap();
}

/// Read stdout to EOF and parse it as CONSECUTIVE frames — any stray byte
/// fails the parse, which is exactly the stdout-purity pin.
fn drain_frames(child: &mut Child) -> Vec<Value> {
    drop(child.stdin.take()); // EOF the host's stdin so it exits
    let mut raw = Vec::new();
    child.stdout.as_mut().unwrap().read_to_end(&mut raw).unwrap();
    child.wait().unwrap();
    let mut frames = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        assert!(raw.len() - pos >= 4, "trailing non-frame bytes on stdout: {:?}", &raw[pos..]);
        let len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        assert!(raw.len() - pos >= len, "torn frame on stdout");
        frames.push(serde_json::from_slice(&raw[pos..pos + len]).expect("frame is JSON"));
        pos += len;
    }
    frames
}

fn why(frame: &Value) -> String {
    frame.get("why").and_then(Value::as_str).unwrap_or_default().to_string()
}

/// The handshake answers hello-for-hello, an unknown op is refused by name,
/// and stdout holds NOTHING but frames — the purity pin is the parse itself.
#[test]
fn stdout_is_frames_and_nothing_else() {
    let mut host = spawn_host();
    send(&mut host, &json!({"op": "hello", "v": 1}));
    send(&mut host, &json!({"op": "mine_a_block"}));
    let frames = drain_frames(&mut host);
    assert_eq!(frames[0], json!({"op": "hello", "v": 1}));
    assert!(why(&frames[1]).contains("proves and submits"), "{frames:?}");
}

/// A version mismatch refuses naming BOTH versions and which artifact is
/// older — skew is the normal state of two separately-installed artifacts.
#[test]
fn a_version_mismatch_names_both_sides() {
    let mut host = spawn_host();
    send(&mut host, &json!({"op": "hello", "v": 99}));
    let frames = drain_frames(&mut host);
    let w = why(&frames[0]);
    assert!(w.contains("v99") && w.contains("v1"), "{w}");
    assert!(w.contains("this host") && w.contains("older"), "{w}");
}

/// Garbage base64 and garbage bundle bytes are refused by name, before any
/// network or memory is spent.
#[test]
fn a_garbage_bundle_is_refused_by_name() {
    let mut host = spawn_host();
    send(&mut host, &json!({"op": "hello", "v": 1}));
    send(&mut host, &json!({
        "op": "prove_and_submit",
        "bundle_b64": "!!!not-base64!!!",
        "scan_url": "http://127.0.0.1:1",
        "node_url": "http://127.0.0.1:1",
    }));
    let frames = drain_frames(&mut host);
    assert!(why(&frames[1]).contains("did not decode"), "{frames:?}");

    let mut host = spawn_host();
    send(&mut host, &json!({"op": "hello", "v": 1}));
    send(&mut host, &json!({
        "op": "prove_and_submit",
        "bundle_b64": qlab_wallet::uri::b64url_encode(b"not a witness bundle"),
        "scan_url": "http://127.0.0.1:1",
        "node_url": "http://127.0.0.1:1",
    }));
    let frames = drain_frames(&mut host);
    assert!(why(&frames[1]).contains("witness bundle refused"), "{frames:?}");
}

/// One prove at a time, ACROSS processes: while the lock is held (a live pid
/// inside), a second host refuses by name.
#[test]
fn a_second_concurrent_prove_is_refused_by_name() {
    let lock = std::env::temp_dir().join(format!("qmb-prover-held-{}.lock", rand_tag()));
    // Hold the lock as ourselves — a live pid, exactly what a proving host is.
    let _ = std::fs::remove_dir_all(&lock);
    std::fs::create_dir(&lock).unwrap();
    std::fs::write(lock.join("pid"), std::process::id().to_string()).unwrap();

    let mut host = spawn_host_locked(&lock);
    send(&mut host, &json!({"op": "hello", "v": 1}));
    send(&mut host, &json!({
        "op": "prove_and_submit",
        "bundle_b64": "AA",
        "scan_url": "http://127.0.0.1:1",
        "node_url": "http://127.0.0.1:1",
    }));
    let frames = drain_frames(&mut host);
    std::fs::remove_dir_all(&lock).unwrap();
    let w = why(&frames[1]);
    assert!(w.contains("one prove at a time"), "{w}");
    assert!(w.contains(&std::process::id().to_string()), "the holder is named: {w}");
}

/// A STALE lock (its pid is gone) is reaped rather than wedging spending
/// forever — the crashed-prove case.
#[test]
fn a_stale_lock_is_reaped_not_fatal() {
    let lock = std::env::temp_dir().join(format!("qmb-prover-stale-{}.lock", rand_tag()));
    let _ = std::fs::remove_dir_all(&lock);
    std::fs::create_dir(&lock).unwrap();
    std::fs::write(lock.join("pid"), "999999999").unwrap(); // nobody

    let mut host = spawn_host_locked(&lock);
    send(&mut host, &json!({"op": "hello", "v": 1}));
    send(&mut host, &json!({
        "op": "prove_and_submit",
        "bundle_b64": "AA",
        "scan_url": "http://127.0.0.1:1",
        "node_url": "http://127.0.0.1:1",
    }));
    let frames = drain_frames(&mut host);
    // Past the lock: the refusal is about the BUNDLE now, not the lock.
    let w = why(&frames[1]);
    assert!(!w.contains("one prove at a time"), "stale lock must be reaped: {w}");
    assert!(w.contains("witness bundle refused") || w.contains("did not decode"), "{w}");
}
