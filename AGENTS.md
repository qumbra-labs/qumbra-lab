# Repository Guidelines

## Scope and Structure

This private Rust 2021 workspace prototypes the Qumbra protocol. The binding specifications live in `qumbra-design`; do not silently diverge from them. Read `README.md` for the crate map and consult `CLAUDE.md` for current gates and historical decisions before substantial work.

Library and protocol crates live in `crates/qlab-*`; shipping binaries and user-facing crates live in `crates/qumbra-*`. Keep production dependency flow from `qumbra-*` toward `qlab-*`. Integration tests belong in each crate's `tests/`; settled evidence and working notes belong in `docs/`. `extraction/qumbra-circuit/` is the self-contained circuit extraction and must stay reproducible.

## Development and Verification

- `cargo fmt --all -- --check` checks formatting.
- `cargo check --workspace --all-targets --locked` is the normal local verification gate.
- `cargo clippy --workspace --all-targets --locked` is advisory; explain any newly introduced warning.
- The acceptance command is `cargo test --release --workspace --locked -- --test-threads=1`, but **agents must never run any `cargo test` locally, even crate-scoped**. Push the PR and use the `verify`/`verify-graviton` CI labels; CI is the acceptance environment.

Use workspace-managed dependencies and preserve `Cargo.lock`. Name modules/functions in `snake_case`, types in `PascalCase`, and constants in `SCREAMING_SNAKE_CASE`. Add regression tests for behavioral changes, especially wire formats, consensus rules, persistence, and cross-crate invariants. Never weaken a release assertion into `debug_assert!`.

## Measurements and Documentation

Benchmarks require the repository revision, prover revisions, hardware, OS, and power state. Publish a number to the design repo only after two same-rig reproductions. Agent sessions may write benchmark code but must not run local test/acceptance workloads.

Pair new run reports, findings, incident analyses, and operator runbooks with `-zh.md`; English is authoritative. Build notes and scratch plans need not be translated.

## Commits and Pull Requests

Use an isolated worktree and a focused branch. Commit subjects are imperative and usually end with an issue/PR reference, for example `wallet: reject redirected genesis (#302)`. PRs must name the governing issue/spec, describe protocol impact, list checks actually run, disclose unrun CI gates, and call out fixture, wire, lockfile, or consensus changes.
