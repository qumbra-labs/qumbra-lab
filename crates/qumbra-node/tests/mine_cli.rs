//! Lab #475: `qumbra-node mine` through the REAL binary.
//!
//! `src/mine.rs`'s unit tests drive the seams directly, which is where the
//! backup gate and the genesis verification are actually pinned. These five
//! exist for the things a seam test structurally cannot see: that the
//! subcommand is dispatched at all, that `--help` names it, that the refusals
//! reach an operator's stderr with a non-zero exit, and — the one that matters
//! most — that the `node.toml` this command writes is a config **the shipped
//! binary's own pre-flight accepts**.
//!
//! 🔴 **No test in this file names a net.** Lab #527 was one net's genesis hash
//! hardwired in `mine.rs`; net-parameterising the binary then turned this file
//! red, because it had been asserting `GenesisFile::new_devnet_t0()` — a second
//! hardwired net identity, one layer out, with exactly the same failure mode at
//! exactly the next cutover. Every genesis identity below is either constructed
//! by the test and handed to the binary via `--genesis-hash`, or read back out
//! of the binary itself via `mine --print-net`. Swapping one net constant for
//! the next net's constant would have been the defect, not the fix.
//!
//! None of them start a node. The one test that reaches the run path hands it a
//! deliberately unbindable listen address, so it fails at the bind — after the
//! config has been written, which is the point being proven.

use std::path::{Path, PathBuf};
use std::process::Command;

use qumbra_node::genesis::GenesisFile;
use qumbra_node::mine::{CONFIG_FILE_NAME, GENESIS_FILE_NAME, WALLET_SUBDIR};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qumbra-node")
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("i475_cli_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("temp dir");
    d
}

/// Put a well-formed genesis in `dir` and return **its own** hash — the value
/// the caller then pins with `--genesis-hash`.
///
/// The returned hash is derived from the bytes this function just wrote, so the
/// pin and the file cannot drift apart and neither of them is a net's name.
/// `new_devnet_t0()` appears here only as a source of bytes that verify offline
/// (a real committee₀, a real frozen block, a canonical encoding); nothing below
/// asserts it is any live net's identity, and `mine` is *told* which identity to
/// enforce rather than asked to remember one.
fn place_a_genesis(dir: &Path) -> String {
    let g = GenesisFile::new_devnet_t0();
    g.write(dir.join(GENESIS_FILE_NAME)).expect("write genesis");
    g.hash_hex()
}

/// A valid rkm for the manual path: the same 64-hex form `qumbra-wallet
/// miner-rkm` prints.
const MANUAL_RKM: &str = "0100000000000000020000000000000003000000000000000400000000000000";

/// 🔴 Acceptance (e), through the process an operator actually runs. `cargo
/// test` gives a child process a piped stdin, which is exactly the
/// non-interactive case: no terminal, no flag, so `mine` must refuse — and the
/// directory must be untouched afterwards.
#[test]
fn a_non_interactive_mine_refuses_to_create_a_wallet_and_leaves_the_dir_empty() {
    let dir = tmp("noninteractive");
    let out = Command::new(bin())
        .args(["mine", "--dir", dir.to_str().unwrap()])
        .output()
        .expect("spawn qumbra-node");

    assert!(!out.status.success(), "a silent wallet creation must not be a success path");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--yes-i-backed-up"), "the refusal names the flag: {stderr}");
    assert!(stderr.contains("Nothing was generated"), "{stderr}");

    assert!(!dir.join(WALLET_SUBDIR).exists(), "no wallet directory");
    assert!(!dir.join(CONFIG_FILE_NAME).exists(), "no config");
    assert!(!dir.join(GENESIS_FILE_NAME).exists(), "the genesis fetch is never reached");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The config `mine` writes is a config THIS binary pre-flights clean — the
/// same `check` a deployed host runs, exercising the real genesis byte-verify,
/// the hash pin and the committee cross-check. This is what acceptance item (a)
/// can honestly claim short of mining a block.
#[test]
fn the_config_mine_writes_passes_the_binarys_own_preflight() {
    let dir = tmp("preflight");
    let pinned = place_a_genesis(&dir);

    // `--rkm` so no wallet and no gate are involved: this test is about the
    // config, and the wallet path has its own. The listen address cannot bind
    // on any platform, so the run path fails immediately after the config has
    // been written — which is precisely the ordering being asserted.
    let out = Command::new(bin())
        .args([
            "mine",
            "--dir",
            dir.to_str().unwrap(),
            // `--genesis-hash` used for exactly what its own doc calls "the
            // no-rebuild path": the identity to enforce is supplied, not
            // remembered from build time. `mine` writes it into `node.toml`, so
            // the `check` below still exercises the real byte-verify — the
            // property this test is actually for.
            "--genesis-hash",
            pinned.as_str(),
            "--rkm",
            MANUAL_RKM,
            "--listen",
            "this-is-not-an-address",
        ])
        .output()
        .expect("spawn qumbra-node");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(!out.status.success(), "an unbindable listen address must fail the run");
    assert!(stdout.contains("qumbra-node mine — preparing"), "{stdout}");
    assert!(stdout.contains("--rkm was given"), "the manual path says so: {stdout}");
    assert!(stdout.contains("already present, verified"), "{stdout}");
    assert!(
        stdout.contains("--genesis-hash on this command line"),
        "the pin's provenance is printed above the genesis step: {stdout}"
    );
    assert!(
        stdout.contains("starting the ordinary run path"),
        "mine must hand off to `run`, not reimplement it: {stdout}"
    );
    // The run path was really entered: its own first line is the startup entry
    // line (lab #300), and it names the config `mine` wrote.
    assert!(
        stdout.contains("qumbra-node starting"),
        "the ordinary run path's entry line must appear: {stdout}"
    );

    let cfg = dir.join(CONFIG_FILE_NAME);
    let text = std::fs::read_to_string(&cfg).expect("mine wrote a config");
    assert!(text.contains("mining = true"), "{text}");
    assert!(text.contains(&format!("miner_rkm = \"{MANUAL_RKM}\"")), "{text}");
    assert!(
        text.contains(&format!("expected_genesis_hash = \"{pinned}\"")),
        "the pin `mine` enforced is the pin it hands to `run`: {text}"
    );

    // Now the claim that matters: the shipped binary accepts it. Re-point the
    // listen address at something bindable first — `check` binds nothing, but a
    // config an operator would be handed should not carry the test's poison.
    let fixed = text.replace("this-is-not-an-address", "127.0.0.1:0");
    std::fs::write(&cfg, fixed).expect("rewrite listen addr");
    let check = Command::new(bin())
        .args(["check", "--config", cfg.to_str().unwrap()])
        .output()
        .expect("spawn qumbra-node check");
    let cout = String::from_utf8_lossy(&check.stdout);
    let cerr = String::from_utf8_lossy(&check.stderr);
    assert!(check.status.success(), "preflight failed: {cout}{cerr}");
    assert!(cout.contains("check: OK"), "{cout}");
    assert!(cout.contains("mining:       true"), "{cout}");
    assert!(
        cout.contains(&pinned),
        "the pre-flight reports the pinned genesis: {cout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Acceptance (d) at the process boundary: a genesis file for another net stops
/// the command with a message an operator can act on, and nothing downstream —
/// no config, no socket — is reached.
#[test]
fn a_genesis_for_another_net_stops_the_command_with_a_named_refusal() {
    let dir = tmp("wrongnet");
    // Both sides of the refusal are constructed here: the identity this run is
    // told to enforce, and a file that is not it. Neither is a net's name.
    let want = GenesisFile::new_devnet_t0().hash_hex();
    let mut other = GenesisFile::new_devnet_t0();
    other.network = format!("{}-imposter", other.network);
    let got = other.hash_hex();
    assert_ne!(got, want, "the imposter must not hash to the pin, or this proves nothing");
    std::fs::write(dir.join(GENESIS_FILE_NAME), other.to_bytes()).expect("write imposter");

    let out = Command::new(bin())
        .args([
            "mine",
            "--dir",
            dir.to_str().unwrap(),
            "--genesis-hash",
            want.as_str(),
            "--rkm",
            MANUAL_RKM,
        ])
        .output()
        .expect("spawn qumbra-node");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success());
    assert!(stderr.contains("DIFFERENT NET"), "{stderr}");
    assert!(stderr.contains(&got), "the refusal names what it got: {stderr}");
    assert!(stderr.contains(&want), "and what it wanted: {stderr}");
    assert!(!dir.join(CONFIG_FILE_NAME).exists(), "no config is written");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same refusal for the invocation the join guide actually advertises —
/// **no pin flags at all** — where the expectation comes from the binary rather
/// than the command line.
///
/// Both sides of the assertion are read out of the binary under test: `mine
/// --print-net` on one side, the refusal on the other. So this names no net
/// either, and it stays true across every cutover — while still failing loudly
/// if the two halves of one binary ever disagree about what net it is for,
/// which is the shape lab #527 shipped.
///
/// It is also the first execution of `--print-net` anywhere. The release lane's
/// artifact gate (`assert-release-artifacts.sh`) greps this output, and until
/// now the greps were matched to it by reading the code that prints it.
#[test]
fn the_baked_expectation_a_no_flag_run_enforces_is_the_one_print_net_reports() {
    let printed = Command::new(bin())
        .args(["mine", "--print-net"])
        .output()
        .expect("spawn qumbra-node");
    assert!(
        printed.status.success(),
        "--print-net answers and exits 0, binding nothing: {}{}",
        String::from_utf8_lossy(&printed.stdout),
        String::from_utf8_lossy(&printed.stderr)
    );
    let report = String::from_utf8_lossy(&printed.stdout);
    let baked = report
        .lines()
        .find_map(|l| l.strip_prefix("genesis hash: "))
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|| panic!("--print-net reports a genesis hash line: {report}"));
    // A parser that matches nothing passes silently; this is what stops that.
    assert_eq!(baked.len(), 64, "a 64-hex pin, not a placeholder or a label: {report}");
    assert!(baked.bytes().all(|b| b.is_ascii_hexdigit()), "{report}");

    let dir = tmp("bakedpin");
    let mut other = GenesisFile::new_devnet_t0();
    other.network = format!("{}-imposter", other.network);
    let got = other.hash_hex();
    assert_ne!(got, baked, "the fixture must not be what this binary expects");
    std::fs::write(dir.join(GENESIS_FILE_NAME), other.to_bytes()).expect("write imposter");

    let out = Command::new(bin())
        .args(["mine", "--dir", dir.to_str().unwrap(), "--rkm", MANUAL_RKM])
        .output()
        .expect("spawn qumbra-node");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success());
    assert!(stderr.contains("DIFFERENT NET"), "{stderr}");
    assert!(stderr.contains(&got), "the refusal names what it got: {stderr}");
    assert!(
        stderr.contains(&baked),
        "the refusal must name the identity --print-net reports, or this binary's own two \
         answers about what net it is for disagree: {stderr}"
    );
    assert!(!dir.join(CONFIG_FILE_NAME).exists(), "no config is written");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `--help` names the subcommand and its backup flag. A command a stranger
/// cannot discover is a command that does not exist for them, and this guide is
/// the CLI's own help by house convention (`docs/join-and-mine.md` §4).
#[test]
fn help_names_mine_and_the_backup_flag() {
    let out = Command::new(bin()).arg("--help").output().expect("spawn qumbra-node");
    // usage() writes to stderr, as every other subcommand's help does.
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("qumbra-node mine --dir DIR"), "{text}");
    assert!(text.contains("--yes-i-backed-up"), "{text}");
    assert!(text.contains("REFUSES"), "the help states the refusal, not just the flag: {text}");
}
