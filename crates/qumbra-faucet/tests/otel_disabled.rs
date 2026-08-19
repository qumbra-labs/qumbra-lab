//! 🔴 **The negative, which is the point**: with no `OTEL_EXPORTER_OTLP_ENDPOINT`,
//! no exporter is constructed and the binary says nothing about it.
//!
//! | claim | where |
//! |---|---|
//! | no env ⇒ no exporter object at all | [`no_endpoint_means_no_exporter_is_constructed`] |
//! | an endpoint ⇒ an exporter, and the posture line says so | same test |
//! | the real binary, run with the env unset, emits no otel noise | [`the_binary_run_without_the_env_says_nothing_about_otel`] |
//! | …and turning it ON does not make it noisy either | same test |
//!
//! **Its own integration binary, on purpose, twice over.** It mutates process
//! environment (so it must not race a test that reads it) and it installs the global
//! `tracing` subscriber (of which a process gets one). Both tests below share this
//! binary and nothing else does.
//!
//! The second test spawns the **real compiled binary** rather than calling a
//! function, because "no noise in output" is a claim about a process's file
//! descriptors and cannot be checked from inside the process that owns them.
//! `keygen` is the vehicle: it is the cheapest subcommand that still runs `main`'s
//! telemetry initialisation, which is why `main` initialises for every subcommand
//! rather than only for `run`.

use std::path::PathBuf;
use std::process::Command;

use qumbra_faucet::telemetry::{Telemetry, OTLP_ENDPOINT_ENV};

/// Tokens that would mean the OTel stack, or something under it, wrote to a stream
/// this service's operator reads. `qumbra-faucet keygen`'s own output contains none
/// of them.
const NOISE: [&str; 7] =
    ["otel", "opentelemetry", "error", "warn", "panic", "failed", "unable"];

fn assert_quiet(what: &str, stdout: &str, stderr: &str) {
    // Long opaque tokens are dropped before scanning. `keygen` prints a ~2 kB bech32
    // receive address derived from FRESH entropy every run, and a random alphabet
    // string that long contains `error` or `warn` often enough to make a substring
    // scan over it a coin flip. Nothing that is actually noise is one word of 64+
    // characters.
    let scannable: String = format!("{stdout}\n{stderr}")
        .split_whitespace()
        .filter(|w| w.len() < 64)
        .collect::<Vec<_>>()
        .join(" ");
    let combined = scannable.to_ascii_lowercase();
    for token in NOISE {
        assert!(
            !combined.contains(token),
            "{what}: `{token}` in the output.\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        );
    }
}

/// 🔴 No endpoint ⇒ **no exporter constructed**. `exporting()` is the observable
/// form of that: it is `true` only on the branch that built one.
#[test]
fn no_endpoint_means_no_exporter_is_constructed() {
    // Both halves in ONE test: they mutate the same process environment, and two
    // tests doing that concurrently is a race whatever the assertions say.
    std::env::remove_var(OTLP_ENDPOINT_ENV);
    let off = Telemetry::init();
    assert!(!off.exporting(), "no {OTLP_ENDPOINT_ENV} must mean no exporter");
    assert_eq!(off.endpoint(), None);
    // The startup banner says plainly that nothing is being exported, rather than
    // leaving an operator to infer it from the absence of a line.
    let line = off.posture_line();
    assert!(line.contains("NOT exported"), "{line}");
    assert!(line.contains(OTLP_ENDPOINT_ENV), "the line must name the knob: {line}");
    off.shutdown();

    // …and with an endpoint, an exporter IS built. The endpoint is a black hole on
    // loopback: nothing is exported here (no spans are created), and the assertion
    // is about which branch ran, not about delivery.
    std::env::set_var(OTLP_ENDPOINT_ENV, "http://127.0.0.1:4318");
    let on = Telemetry::init();
    assert!(on.exporting(), "an endpoint must construct an exporter");
    assert_eq!(on.endpoint(), Some("http://127.0.0.1:4318"));
    assert!(on.posture_line().contains("http://127.0.0.1:4318"), "{}", on.posture_line());
    on.shutdown();

    // An empty or whitespace-only value is treated as unset rather than as an
    // endpoint named "". A blank env var in a compose file is the commonest way to
    // "turn something off", and it must not turn export half on.
    std::env::set_var(OTLP_ENDPOINT_ENV, "   ");
    let blank = Telemetry::init();
    assert!(!blank.exporting(), "a blank endpoint is unset, not an endpoint");
    blank.shutdown();

    std::env::remove_var(OTLP_ENDPOINT_ENV);
}

/// 🔴 The real binary, with the env unset, is **silent about telemetry** — and stays
/// silent when it is switched on.
#[test]
fn the_binary_run_without_the_env_says_nothing_about_otel() {
    let dir: PathBuf = std::env::temp_dir()
        .join(format!("qmb-tracing-off-{}-{}", std::process::id(), line!()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");

    let run = |extra_env: Option<&str>, out: &PathBuf| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_qumbra-faucet"));
        cmd.arg("keygen").arg("--out").arg(out);
        // Every OTLP knob cleared, not just the one under test: a runner that
        // happens to export traces itself must not make this test lie either way.
        for k in [
            OTLP_ENDPOINT_ENV,
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            "OTEL_RESOURCE_ATTRIBUTES",
            "OTEL_SDK_DISABLED",
            "RUST_LOG",
        ] {
            cmd.env_remove(k);
        }
        if let Some(endpoint) = extra_env {
            cmd.env(OTLP_ENDPOINT_ENV, endpoint);
        }
        let o = cmd.output().expect("run qumbra-faucet keygen");
        (
            o.status.success(),
            String::from_utf8_lossy(&o.stdout).to_string(),
            String::from_utf8_lossy(&o.stderr).to_string(),
        )
    };

    // (1) Export off — the default, and the configuration the fleet runs today.
    let off_dir = dir.join("off");
    std::fs::create_dir_all(&off_dir).expect("dir");
    let (ok, stdout, stderr) = run(None, &off_dir);
    assert!(ok, "keygen must succeed:\n{stderr}");
    assert!(stdout.contains("qumbra-faucet keygen"), "{stdout}");
    assert_quiet("export disabled", &stdout, &stderr);

    // (2) Export on, pointed at a port nothing is listening on. Still nothing on
    // the operator's streams: `internal-logs` is off and no `fmt` layer exists, so
    // there is no path from the SDK to a file descriptor. The cost of that — a
    // failing export is silent — is named in the PR rather than hidden here.
    let on_dir = dir.join("on");
    std::fs::create_dir_all(&on_dir).expect("dir");
    let (ok, stdout, stderr) = run(Some("http://127.0.0.1:1"), &on_dir);
    assert!(ok, "keygen must succeed with export on:\n{stderr}");
    assert_quiet("export enabled, collector unreachable", &stdout, &stderr);

    let _ = std::fs::remove_dir_all(&dir);
}
