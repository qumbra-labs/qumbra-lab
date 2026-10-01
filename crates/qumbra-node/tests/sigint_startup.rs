//! F5-6 box run 3: a SIGINT that reaches `qumbra-node run` **during startup**
//! must stop it — including when the process inherited SIGINT as ignored, which
//! is what a non-interactive shell gives a command it runs in the background
//! (`node … &` in a script; POSIX). Before the fix the handler was installed only
//! after the genesis load, the datadir open and the replay, so a stop in that
//! window was discarded and the node ran on.
//!
//! The child is started exactly that way: `sh -c 'trap "" INT; exec …'` (an
//! ignored disposition survives `exec`). The test waits for the entry line —
//! the handler is armed before it is written — then sends SIGINT and requires
//! the process to end: by the startup exit (130) when the signal lands before
//! the loop, or by the graceful flush when it lands after. Either way, never a
//! node that keeps running.
#![cfg(unix)]

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

fn stage(base: &Path) -> PathBuf {
    let _ = std::fs::remove_dir_all(base);
    std::fs::create_dir_all(base.join("data")).unwrap();
    let ok = Command::new(bin()).args(["genesis", "init", "--out"]).arg(base).status().expect("spawn genesis init");
    assert!(ok.success(), "genesis init");
    let cfg = format!(
        "data_dir = \"{}\"\nlisten_addr = \"127.0.0.1:0\"\ngenesis_file = \"{}\"\nmining = false\ndiscovery_addr = \"off\"\n",
        base.join("data").display(),
        base.join("genesis.qmb").display(),
    );
    let path = base.join("node.toml");
    std::fs::write(&path, cfg).unwrap();
    path
}

#[test]
fn a_sigint_during_startup_stops_a_node_that_inherited_sigint_ignored() {
    let base = std::env::temp_dir().join(format!("f56_sigint_startup_{}", std::process::id()));
    let cfg = stage(&base);
    let mut child = Command::new("sh")
        .args(["-c", "trap '' INT; exec \"$0\" run --config \"$1\" --rehearsal-verifier --sample-interval-secs 3600"])
        .arg(bin())
        .arg(&cfg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sh");
    // The entry line is the first stdout line (lab #300); the handler is armed
    // before it is written.
    let mut stdout = child.stdout.take().unwrap();
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    while !seen.contains(&b'\n') {
        assert_eq!(stdout.read(&mut byte).expect("read stdout"), 1, "the node printed its entry line before ending");
        seen.push(byte[0]);
    }
    let kill = Command::new("kill").args(["-INT", &child.id().to_string()]).status().expect("kill");
    assert!(kill.success());
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("SIGINT during startup was swallowed: the node still runs 60 s later");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut rest = String::from_utf8_lossy(&seen).into_owned();
    let _ = stdout.read_to_string(&mut rest);
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    let startup_exit = status.code() == Some(130) && format!("{rest}{err}").contains("stop requested during startup");
    let graceful = status.success() && rest.contains("shutdown complete");
    assert!(startup_exit || graceful, "status {status:?}; stdout {rest}; stderr {err}");
    let _ = std::fs::remove_dir_all(&base);
}
