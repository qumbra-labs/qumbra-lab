//! `qumbra-opview` — read `/v1/telemetry` from a list of nodes and say whether
//! they agree on what they finalized (issue #117).
//!
//! ```text
//! qumbra-opview node0=http://127.0.0.1:9410 node1=http://127.0.0.1:9411
//! qumbra-opview --endpoints ./nodes.txt --timeout-ms 5000
//! ```
//!
//! Exit codes: `0` = no critical divergence (including when nodes are down or an
//! `sid` split was found), `2` = 🔴 `fid` or exact supply divergence, `1` = bad
//! usage. Only a STOP-grade finding is non-zero — an operator wiring this into an
//! alert must not be paged because a node is down or because a routine
//! signed-variant split was recorded.
//!
//! # `0` is "nothing divergent was detected", not "supply was verified" (#136)
//!
//! A node whose state ledger trails fork choice reports coverage
//! `Unavailable`, its figures are refused rather than rendered
//! (#130), and `render::supply_diverged` correctly declines to fire on partial
//! evidence — so **exit `0` covers both "supply was checked across the whole
//! canonical chain and agreed" and "supply was never checked".** The exit status
//! cannot tell those apart, and it is not meant to: **coverage is reported in the
//! output, not in the exit status.** A consumer that needs to know greps the
//! supply block for `UNAVAILABLE`, which is a **stable token alerting may depend
//! on** and is pinned by a test on both sides (present under partial coverage,
//! absent under complete coverage). A node rendered `UNREACHABLE` is uncovered
//! too — it contributed no supply evidence at all — so a consumer asking "was
//! everything checked?" reads both tokens; that one is pinned by
//! `unreachable_renders_as_unreachable_and_never_as_a_dissent`.
//!
//! Deliberately **not** a third exit code, and deliberately not promoted to `2`:
//! every joining or briefly-lagging node reports `Unavailable`, so a non-zero
//! code here would ring continuously and train operators to ignore the one code
//! that means STOP — strictly worse than this silence, and against #117's
//! convention that only a STOP-grade finding is non-zero.

use std::process::ExitCode;
use std::time::Duration;

use qumbra_opview::agree::Agreement;
use qumbra_opview::poll::{poll_all, Endpoint, PollOptions, DEFAULT_TIMEOUT};
use qumbra_opview::render;

const USAGE: &str = "\
qumbra-opview — read-only chain health + supply attestation (issues #117/#121)

USAGE:
    qumbra-opview [OPTIONS] <ENDPOINT>...

ENDPOINT:
    [label=]http://host:port     e.g. node0=http://127.0.0.1:9410
                                 a bare host:port is assumed http://

OPTIONS:
    --endpoints <FILE>   read endpoints from a file, one per line
                         (`#` comments and blank lines ignored)
    --timeout-ms <N>     per-node deadline for connect/write/read [default: 3000]
    -h, --help           this text

EXIT:
    0  no critical divergence was DETECTED (nodes may be down; an sid split is a
       finding; supply coverage may be incomplete — see below)
    2  fid divergence (R2 STOP) or non-zero scheduled-supply divergence
    1  usage error

Exit 0 does not assert that supply was verified. A node whose state ledger trails
fork choice reports coverage UNAVAILABLE and its supply figures are refused, which
also exits 0 — so the exit status alone cannot tell `checked across the whole
canonical chain and agreed` from `never checked`. Coverage is reported in the
output, not in the exit status: grep the supply block for UNAVAILABLE. That token
is stable and alerting may depend on it. A node rendered UNREACHABLE contributed
no supply evidence either, so `was everything checked?` reads both tokens.
UNAVAILABLE is deliberately not a third exit code — every joining or briefly
lagging node is UNAVAILABLE, so paging on it would train operators to ignore the
one code that means STOP.

This view exposes only public chain facts. It deliberately has no address,
balance, or traceable-transfer pages because Qumbra has no transparent tier.
`These N nodes agree` is not the same claim as `the whole network agrees`.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("qumbra-opview: {e}\n\n{USAGE}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut timeout = DEFAULT_TIMEOUT;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "--timeout-ms" => {
                let v = args.get(i + 1).ok_or("--timeout-ms needs a value")?;
                let ms: u64 = v.parse().map_err(|_| format!("--timeout-ms {v}: not a number"))?;
                timeout = Duration::from_millis(ms);
                i += 2;
            }
            "--endpoints" => {
                let path = args.get(i + 1).ok_or("--endpoints needs a path")?;
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("--endpoints {path}: {e}"))?;
                for line in text.lines() {
                    let line = line.split('#').next().unwrap_or("").trim();
                    if !line.is_empty() {
                        endpoints.push(Endpoint::parse(line)?);
                    }
                }
                i += 2;
            }
            other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
            other => {
                endpoints.push(Endpoint::parse(other)?);
                i += 1;
            }
        }
    }
    if endpoints.is_empty() {
        return Err("no endpoints given".to_string());
    }

    let readings = poll_all(&endpoints, PollOptions { timeout });
    let agreement = Agreement::of(&readings);
    print!("{}", render::view(&readings, &agreement));
    // `critical` is "a divergence was DETECTED". It is deliberately NOT "supply
    // was verified": under `SupplyCoverage::Unavailable` the figures are refused,
    // `supply_diverged` is false, and this exits 0 — the same 0 a fully covered,
    // agreeing net produces. Coverage lives in the output above, as the
    // `UNAVAILABLE` token, and the `EXIT:` block says so (issue #136).
    let critical = agreement.exit_code() != 0 || render::supply_diverged(&readings);
    Ok(ExitCode::from(if critical { 2 } else { 0 }))
}

#[cfg(test)]
mod tests {
    use super::USAGE;

    /// **Issue #136: the operator text is the only thing that tells a script author
    /// exit `0` is not a coverage assertion** — so pin the two claims a consumer
    /// depends on. `UNAVAILABLE` is the token an alert greps (rendered by
    /// `render::supply`, pinned on both sides in that module's tests); this text is
    /// what points anyone at it. Rewording the `EXIT:` block is fine, silently
    /// dropping either claim is not.
    ///
    /// Same reason PR #126 pinned `!text.contains("AGREED")`: a later reword must
    /// not be able to break a consumer without breaking a test first.
    #[test]
    fn usage_says_exit_zero_does_not_attest_supply_coverage() {
        assert!(
            USAGE.contains("Exit 0 does not assert that supply was verified."),
            "the EXIT: block must state what 0 does not claim:\n{USAGE}"
        );
        assert!(
            USAGE.contains("UNAVAILABLE"),
            "the EXIT: block must name the token a consumer greps for coverage:\n{USAGE}"
        );
    }
}
