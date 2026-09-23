# qumbra-lab

The prototype lab behind **Qumbra**, a post-quantum privacy-chain design exercise. This is
the repository where the design's open questions were answered with measured code: the
transaction circuit, the node, the P2P layer, the wallet, the faucet, the pool, and the
tooling that ran a small public testnet across three continents between July and August 2026.

> **Status (2026-09-22): development is paused, as of 2026-08-29.** The code is published
> as it stood on that day. The T2 testnet fleet is no longer operated; its public endpoints
> may still answer, but treat anything they say as stale. There is no token, testnet coins
> have no value, and nothing in this repository is an offer of anything. Read it as a
> research record.

## Where to start if you are new

Qumbra was published in stages, and the pieces a stranger can verify without this repo are
in two public sibling repositories. Start there:

- [`qumbra-labs/qumbra`](https://github.com/qumbra-labs/qumbra) — the protocol spec, the
  whitepaper, the consensus parameters (`docs/spec/`), and the T2 testnet release binaries.
- [`qumbra-labs/qumbra-circuit`](https://github.com/qumbra-labs/qumbra-circuit) — the
  transaction circuit (`qlab-air`, byte-identical to the copy here) plus the consensus
  verifier and a committed real proof you can check with `cargo run --example verify`.

This repo is the working tree those were extracted from. It is larger, messier, and more
honest: the bench notes, the incident write-ups, and the milestone log are all here.

The design documents that bind this code (22 paired EN/ZH design docs plus appendices) live
in a separate repository that is **not public**. Where a file here cites them by name, the
`docs/spec/` copy in `qumbra-labs/qumbra` is the published subset.

## What Qumbra is, in one paragraph

A 2026 greenfield design for a post-quantum privacy L1: note-based UTXO, one global shielded
pool (no transparent tier, no rings), one monolithic STARK per transaction with spend
authorization inside the proof (no per-spend signatures), conservative Keccak/SHA-class
hashing everywhere in consensus, ML-KEM note encryption, and hybrid PoW plus a small BFT
finality committee. The bet is that hash-based STARKs plus NIST-standard components beat
lattice ring signatures on every engineering axis. The circuit is a raw fixed-shape AIR,
deliberately not a zkVM.

## What was built and measured

Every number below is from the milestone log (`CLAUDE.md` for M10 onward,
[`docs/milestone-log.md`](docs/milestone-log.md) for M1 to M9), with the issue or PR that
produced it. Hardware and revision are recorded at the source; nothing here is rounded.

- **The consensus transaction proof is 148,625 bytes on the wire**, frozen and locked for
  the T1 and T2 nets. One real proof is committed in `qumbra-circuit`.
- **A single 2×2 grant proof takes 2.11 s at 11.89 GB peak RSS** on the faucet path
  (issue #123, PR #128, one sample, release build). A consensus prove on the mint path
  measured 3.06 s at 12.21 GB (PR #252, one sample).
- **Two-level proof aggregation runs end to end**: leaf 839.2 KB, interior root 1.65 MB,
  interior peak memory 19.75 to 20.42 GB against a 32 GB envelope (issue #24, PR #82).
- **The node ran a 48.01-hour WAN soak on four AWS `t4g.small` hosts across three continents**
  with zero restarts and zero finality reversions; LWMA difficulty at WAN pacing measured over
  1,707 intervals, mean 86 s against a 75 s target (PR #93).
- **Checkpoint sync let a from-genesis stranger join in minutes rather than hours** by
  skipping RandomX re-validation below quorum finality (issue #412, PR #418).
- **A height-keyed rule change was crossed on a running chain without a halt**: the emission
  boundary at height 8,640 on 2026-08-12 (`docs/emission-boundary-index.md`). The second such
  change, the name-service rule, never crossed live: its straddle drill found a deadlock in
  the suite four days before the fleet would have hit it (PR #464), and T2 shipped the rule
  native from genesis instead. That is what the drills were for.
- **T2 was minted from a fresh genesis on 2026-08-18** (PR #472) and cut over on 2026-08-21,
  with public CPU mining through a Monero-convention stratum pool and a proof-generating
  faucet. T1, the first net, was retired the day before; nothing carried over.

Things it deliberately is not: not a transaction explorer (a single shielded pool has nothing
to look up), not a zkVM, not a lattice-signature chain, and not a product.

## Layout

```
crates/                          29 crates in one workspace
  qlab-air/                      the fixed-shape AIR: Merkle path, PRF, commitment, balance
  qlab-consensus/                the frozen CONSENSUS_CFG + prove/verify wrappers (single source)
  qlab-l2/                       the L2 (Annulet) consensus crate: shapes S/P v1 pins, provisional lane, prove/verify
  qlab-bench/                    bench harness: hash matrix × hardware, criterion-based
  qlab-pow/                      RandomX (light) + Zawy LWMA-1, exact integer form
  qlab-p2p/                      wire envelope, peer table, gossip, sync, discovery, transports
  qlab-node/                     node state, mempool, emission, finality recovery, RPC
  qlab-devnet/                   chain sim, committee/epoch machinery, vote tally
  qlab-wallet/                   key hierarchy, bech32m addresses, HD seed, diversifiers
  qlab-ledger/                   the wallet's own ledger, shared by every shell (CLI, iOS, extension)
  qlab-note/                     ML-KEM-768 + ChaCha20-Poly1305 note encryption
  qlab-cbserver/                 compact-block server (interop-spec §2 reference)
  qlab-disclosure/               selective-disclosure STARK
  qlab-econ/                     emission simulator
  qlab-demo/                     whole-stack composition
  qlab-faucet/                   faucet core: a proof-generating wallet + off-chain anti-abuse
  qlab-stratum/                  Monero-convention stratum codec (pool protocol lib; no I/O)
  qlab-http-framing/             HTTP/1.1 response framing for the hand-rolled clients
  qlab-vask/                     exchange/VASP kit: envelope verifier lib + C ABI (see its README)
  qlab-remote-auth/              research-only remote-authorization spike (not production-reachable)
  qlab-remote-auth-mobile-bench/ isolated iOS/Android measurement ABI for that spike
  qumbra-node/                   the shipping node binary: config, genesis, run
  qumbra-wallet/                 the end-user wallet CLI: keygen/restore/address/backup/scan/send
  qumbra-ffi/                    the wallet kernel over a C ABI, cross-compiled for iOS and wasm
  qumbra-faucet/                 the testnet faucet listener, in-process with a keyless node
  qumbra-pool/                   the T2 pool binary: TCP stratum + accounting + template source
  qumbra-explorer/               the public chain-health JSON projection over a keyless observer node
  qumbra-opview/                 the operator view: cross-node checkpoint agreement + supply attestation
  qumbra-prover-service/         shared proving mechanics for valueless nets: bounded jobs, no submit
  qumbra-credit-ref/             the exchange crediting-flow reference over qlab-vask
docs/                            lab notes: bench runs, incident write-ups, after-actions (EN, with -zh pairs)
deploy/                          the node's compose/systemd shape and a deploy dry-run; the fleet's real config lived elsewhere
extraction/                      the standalone tree that became qumbra-circuit, as extracted from here
.github/workflows/               CI: a free prefilter on every PR, the acceptance suite on a labelled PR, image and release lanes
```

## Building and testing

Rust stable (CI last ran on 1.95) plus `cmake` and a C++ toolchain, which `randomx-rs` needs.
There is no `rust-toolchain.toml` on purpose; bench numbers are recorded against the exact
prover revisions in `Cargo.lock`, and the lockfile is the pin.

```sh
cargo check --workspace --all-targets --locked
cargo test --release --locked -p qlab-pow --lib -- --test-threads=1
```

Two things to know before running the whole suite:

- **Run tests single-threaded.** Several `qumbra-node` tests spawn the real binary with the
  real M3 verifier and generate real STARK proofs; each one wants roughly 12 GB of memory
  and a few seconds to a few minutes. Two at once will exhaust a laptop. `--test-threads=1`
  is not optional.
- **The full acceptance bar is `cargo test --release --workspace --locked --no-fail-fast`**
  and it was run on a dedicated arm64 machine, not on developer laptops or the free CI lane.
  `docs/ci-runner-cost-decision.md` explains why. The PR prefilter only checks that the
  workspace builds, that the wallet core stays buildable for `wasm32-unknown-unknown`, and
  runs clippy as advisory.

## Reading the history

- [`docs/milestone-log.md`](docs/milestone-log.md) — M1 to M9, the settled part: hash
  selection, circuit sizing, soundness accounting, aggregation.
- [`CLAUDE.md`](CLAUDE.md) — M10 onward: the node, the two testnets, and the bench
  discipline. It was written to orient the coding agents that did most of the typing, so it
  reads as operating instructions, and it names the project owner throughout. It is kept as
  the record it is.
- [`docs/join-and-mine.md`](docs/join-and-mine.md) — how a stranger joined T2 while it ran.
- [`docs/after-action-2026-08-15-sync-wall.md`](docs/after-action-2026-08-15-sync-wall.md),
  `docs/incident-2026-08-05-finality-night.md`, `docs/incident-2026-08-02-t0-wan-7-roll.md` —
  the things that went wrong, written up at the time.
- [`docs/backend-assisted-proving-security.md`](docs/backend-assisted-proving-security.md)
  and [`docs/hash-ots-spend-authorization.md`](docs/hash-ots-spend-authorization.md) — the
  two open research threads at the pause.

Issue and PR numbers in this repo refer to this repo unless prefixed otherwise. References
to `qumbra-design` and `qumbra-deploy` point at private repositories and will not resolve.

## Ground rules that shaped the code

- Every bench result records the git revision of this repo, the prover crate revisions,
  hardware, OS, and power state. A number without those is not a result.
- A number is published only after it has been reproduced twice on the same rig.
- The circuit is one fixed shape. No generality, no zkVM; `qlab-air` implements exactly the
  statement in the design and nothing else.

## License

This repository is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your
option. This matches the terms of the qumbra and qumbra-circuit repositories.
