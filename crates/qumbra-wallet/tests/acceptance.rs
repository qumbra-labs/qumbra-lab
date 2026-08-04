//! The CLI as a real process (issue #243): real argv, real stdin, captured
//! stdout — because the two disciplines this tool exists for (key material
//! never on stdout by default; restore via stdin never argv) are claims about
//! the PROCESS boundary, and only a spawned process can test them.
//!
//! Plus one scan integration over the reference devnet fixture, in-process via
//! `scan_local` — the same function the HTTP path runs, over a different fetch.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use qlab_cbserver::client::{scan_local, Completeness, ScanConfig};
use qlab_cbserver::data::{Devnet, GenParams};
use qumbra_wallet::store::{reveal_mnemonic, WalletDir};
use qumbra_wallet::view::{render, DivScan, UNAVAILABLE};

const BIN: &str = env!("CARGO_BIN_EXE_qumbra-wallet");

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("qmb_wcli_{tag}"));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn run(args: &[&str], stdin: Option<&str>) -> (String, String, bool) {
    let mut cmd = Command::new(BIN);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd.spawn().expect("spawn");
    if let Some(input) = stdin {
        child.stdin.take().unwrap().write_all(input.as_bytes()).expect("stdin");
    }
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

#[test]
fn keygen_prints_an_address_and_no_key_material_and_backup_needs_reveal() {
    let dir = tmp("proc1");
    let d = dir.to_str().unwrap();

    let (stdout, stderr, ok) = run(&["keygen", "--dir", d], None);
    assert!(ok, "{stderr}");
    assert!(stdout.contains("address [0]"), "{stdout}");
    assert!(stdout.contains("qaddr1"), "a bech32m address is printed (ADDR_HRP)");

    // The claim, tested at the process boundary: nothing key-shaped escaped.
    let w = WalletDir::open(&dir).unwrap();
    let mnemonic = reveal_mnemonic(&w);
    let combined = format!("{stdout}{stderr}");
    assert!(!combined.contains(&mnemonic), "the mnemonic never leaves keygen");
    let entropy_hex: String = w.seed.entropy().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!combined.to_lowercase().contains(&entropy_hex), "no entropy hex either");

    // backup refuses without the explicit flag…
    let (_, err2, ok2) = run(&["backup", "--dir", d], None);
    assert!(!ok2);
    assert!(err2.contains("--reveal"), "{err2}");
    // …and prints exactly the phrase with it.
    let (out3, _, ok3) = run(&["backup", "--dir", d, "--reveal"], None);
    assert!(ok3);
    assert_eq!(out3.trim(), mnemonic);
}

#[test]
fn restore_reads_stdin_never_argv_and_reproduces_the_address() {
    let d1 = tmp("proc2a");
    let (out1, _, ok1) = run(&["keygen", "--dir", d1.to_str().unwrap()], None);
    assert!(ok1);
    let addr0 =
        out1.lines().find(|l| l.trim().starts_with("qaddr1")).unwrap().trim().to_string();
    let phrase = reveal_mnemonic(&WalletDir::open(&d1).unwrap());

    let d2 = tmp("proc2b");
    // The phrase travels on STDIN. There is no argv form to misuse: `restore`
    // takes only --dir, which this invocation demonstrates.
    let (out2, err2, ok2) = run(&["restore", "--dir", d2.to_str().unwrap()], Some(&phrase));
    assert!(ok2, "{err2}");
    assert!(out2.contains(&addr0), "same seed, same address 0\n{out2}");
}

#[test]
fn a_bip39_phrase_is_refused_through_the_real_process() {
    let d = tmp("proc3");
    let bip39 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                 abandon abandon about";
    let (_, stderr, ok) = run(&["restore", "--dir", d.to_str().unwrap()], Some(bip39));
    assert!(!ok);
    assert!(stderr.contains("NOT BIP-39"), "{stderr}");
}

#[test]
fn address_new_allocates_and_the_set_survives_via_the_process() {
    let dir = tmp("proc4");
    let d = dir.to_str().unwrap();
    run(&["keygen", "--dir", d], None);
    let (out, _, ok) = run(&["address", "--dir", d, "--new"], None);
    assert!(ok);
    assert!(out.contains("address [1]"), "{out}");
    let (list, _, _) = run(&["address", "--dir", d], None);
    assert!(list.contains("[0]") && list.contains("[1]"), "{list}");
}

#[test]
fn miner_rkm_matches_the_node_config_form_and_names_unallocated_indices() {
    let dir = tmp("rkm");
    let d = dir.to_str().unwrap();
    run(&["keygen", "--dir", d], None);

    let (out, _, ok) = run(&["miner-rkm", "--dir", d], None);
    assert!(ok);
    let hex_line = out.lines().find(|l| l.contains("miner_rkm = ")).unwrap();
    let hex = hex_line.split('"').nth(1).unwrap();
    assert_eq!(hex.len(), 64, "the 64-hex lane-major LE form NodeConfig parses");

    // Byte-for-byte against the library derivation at index 0's diversifier.
    let wallet = WalletDir::open(&dir).unwrap().wallet();
    let d0 = wallet.diversifier_at_index(0);
    let expect: String = qlab_note::hash::digest_bytes(&wallet.rkm(d0))
        .iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, expect, "the printed rkm IS address [0]'s identity");

    // An unallocated index is valid but SAID to be outside the scan set.
    let (out5, err5, ok5) = run(&["miner-rkm", "--dir", d, "--index", "5"], None);
    assert!(ok5);
    assert!(err5.contains("not in this wallet's allocated set"), "{err5}");
    let hex5 = out5.lines().find(|l| l.contains("miner_rkm = ")).unwrap();
    assert_ne!(hex5, hex_line, "different index, different identity");
}

#[test]
fn scan_against_the_reference_fixture_renders_a_complete_report() {
    // The reference devnet pays its own key; scanning with that key through THIS
    // crate's reduction + render is the integration the report path needs. The
    // same fn runs over HTTP (`light_client_scan` is `scan_over` with a socket
    // fetch) — the wallet-owned-key-over-HTTP flow stays gated on #188 4/4 and
    // is disclosed as not-verified in the PR.
    let devnet = Devnet::generate(GenParams::default());
    let tip = devnet.tip_height();
    let mut rng = <rand::rngs::StdRng as rand::SeedableRng>::seed_from_u64(7);
    let outcome = scan_local(&devnet, &devnet.our.dk, 0, tip, ScanConfig::default(), &mut rng);
    assert!(matches!(outcome.completeness(), Completeness::Complete | Completeness::Shadowed { .. }));

    let scan = DivScan::from_outcome(0, "qmbs1fixture".into(), &outcome);
    let spendable = scan.spendable_bessel;
    assert!(spendable > 0, "the fixture pays its own key");
    let report = render(&[scan], (0, tip), "in-process");
    assert!(report.contains(&format!("TOTAL spendable: {spendable} bessel")), "{report}");
    assert!(!report.contains(UNAVAILABLE), "{report}");
}
