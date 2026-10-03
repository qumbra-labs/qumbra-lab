//! `qumbra-sequencer` — the binary half (lab #847). S1b ships the library; the
//! intake (S2) and the posting loop (S4) arrive as subcommands. Until then
//! the binary names what it is and refuses everything else by name, so a
//! deployment script that calls it learns that, rather than seeing a no-op.
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") => {
            println!("qumbra-sequencer {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "qumbra-sequencer: no commands yet — the intake and the posting loop land in lab #847 S2/S4; \
                 bundles are built with `qlab-bench f5box` until then"
            );
            ExitCode::from(64)
        }
    }
}
