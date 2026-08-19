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
    // Lab #512: the entry line arrives behind the native UTC journal stamp
    // (`YYYY-MM-DDTHH:MM:SS.mmmZ `, 24 chars + a space), so the anchor is the
    // stamped shape, not line start — and this test is what locks the stamp
    // through the REAL binary.
    assert_eq!(
        (first.as_bytes().get(10), first.as_bytes().get(23), first.as_bytes().get(24)),
        (Some(&b'T'), Some(&b'Z'), Some(&b' ')),
        "the FIRST stdout line must open with the UTC journal stamp; got {first:?}"
    );
    assert!(
        first[25..].starts_with("qumbra-node starting"),
        "the FIRST stdout line must be the (stamped) entry line; got {first:?} (stdout: {stdout:?})"
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
        // TOML **literal** strings for the paths (lab #478). A basic string
        // treats `\` as an escape, so on Windows this fixture's own temp path
        // would make the config unparseable and the test would fail for a
        // reason that has nothing to do with what it is testing. Latent today —
        // the windows CI leg runs `--lib` only — and fixed here so it stays that
        // way rather than waiting to be rediscovered.
        format!(
            "data_dir = '{}'\nlisten_addr = \"127.0.0.1:0\"\ngenesis_file = '{}'\n",
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
    // Content anchors, not line-start (lab #512: both lines carry the UTC
    // journal stamp); the ordering property — entry line first, genesis
    // bracket second — is unchanged and is still what this test proves.
    assert!(first.contains("qumbra-node starting"), "first line: {first:?}");
    assert!(
        second.contains("STARTUP loading genesis file"),
        "second line must be the genesis-stage begin bracket: {second:?}"
    );
}
