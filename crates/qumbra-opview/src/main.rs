//! `qumbra-opview` — read `/v1/telemetry` from a list of nodes and say whether
//! they agree on what they finalized (issue #117).
//!
//! ```text
//! qumbra-opview node0=http://127.0.0.1:9410 node1=http://127.0.0.1:9411
//! qumbra-opview --endpoints ./nodes.txt --timeout-ms 5000
//! ```
//!
//! Exit codes: `0` = no `fid` divergence (including when nodes are down or an
//! `sid` split was found), `2` = 🔴 `fid` divergence, `1` = bad usage. Only the
//! STOP is non-zero — an operator wiring this into an alert must not be paged
//! because a node is down or because a routine signed-variant split was recorded.

use std::process::ExitCode;
use std::time::Duration;

use qumbra_opview::agree::Agreement;
use qumbra_opview::poll::{poll_all, Endpoint, PollOptions, DEFAULT_TIMEOUT};
use qumbra_opview::render;

const USAGE: &str = "\
qumbra-opview — T0 operator view: cross-node checkpoint agreement (issue #117)

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
    0  no fid divergence (nodes may be down; an sid split is a finding, not a stop)
    2  fid divergence — two checkpoints finalized at one height (R2 STOP)
    1  usage error

This is the T0 operator view over YOUR OWN nodes. It is not a transaction
explorer, and `these N nodes agree` is not the same claim as `the chain is
healthy` on any net where the list is not the whole network.
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
    Ok(ExitCode::from(agreement.exit_code() as u8))
}
