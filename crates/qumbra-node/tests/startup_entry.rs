//! Lab #300: the entry line precedes config load — proven through the REAL
//! binary, not a seam. `qumbra-node run` pointed at a config that cannot load
//! must still print the entry line, because the line is written before the load
//! is attempted; if the ordering ever regresses (someone hoists work above the
//! announce), the line vanishes from this exact invocation and this test fails.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

#[test]
fn the_entry_line_appears_even_when_the_config_cannot_load() {
    let out = Command::new(bin())
        .args(["run", "--config", "/nonexistent/i300/definitely-missing.toml"])
        .output()
        .expect("spawn qumbra-node");
    assert!(!out.status.success(), "a missing config must still fail the run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let first = stdout.lines().next().unwrap_or("");
    assert!(
        first.starts_with("qumbra-node starting"),
        "the FIRST stdout line must be the entry line; got {first:?} (stdout: {stdout:?})"
    );
    assert!(
        first.contains("/nonexistent/i300/definitely-missing.toml"),
        "the entry line must name the config it is about to read: {first:?}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("config"), "the load failure still reports on stderr: {stderr:?}");
}

/// With a config that loads but a genesis that does not, stdout must read
/// entry line → genesis-stage begin line → (failure on stderr): the stage
/// brackets sit in the right order relative to the entry line, and a stall in
/// genesis load would present as "begun, not done" rather than as silence.
#[test]
fn the_genesis_stage_line_follows_the_entry_line() {
    let dir = std::env::temp_dir().join(format!("i300-entry-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let cfg = dir.join("node.toml");
    std::fs::write(
        &cfg,
        format!(
            "data_dir = \"{}\"\nlisten_addr = \"127.0.0.1:0\"\ngenesis_file = \"{}\"\n",
            dir.join("data").display(),
            dir.join("missing-genesis.qmb").display()
        ),
    )
    .expect("write config");

    let out = Command::new(bin())
        .args(["run", "--config", cfg.to_str().expect("utf-8 path")])
        .output()
        .expect("spawn qumbra-node");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(!out.status.success(), "a missing genesis must still fail the run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut lines = stdout.lines();
    let first = lines.next().unwrap_or("");
    let second = lines.next().unwrap_or("");
    assert!(first.starts_with("qumbra-node starting"), "first line: {first:?}");
    assert!(
        second.starts_with("STARTUP loading genesis file"),
        "second line must be the genesis-stage begin bracket: {second:?}"
    );
}
