# qlab-devnet load-test — measured run 2 (reproduction, issue #42)

Reproduction of `devnet-load-run1.md`. Same rig, same runner, fresh process.

## Environment

- repo: branch `claude/devnet-load`, sub-phases A–F (unchanged from run 1)
- hardware: Apple M5 Max, 36 GiB · OS Darwin 25.5.0 · AC
- command: `cargo run --release -p qlab-devnet --bin load` (fresh invocation)

## Result: byte-for-byte identical

The load sweeps are **deterministic** — every draw comes from a seeded
`SplitMix64` with no wall-clock or entropy input — so reproduction is *exact*, not
"within jitter":

```
$ cargo run --release -q -p qlab-devnet --bin load 2>/dev/null > run1.txt
$ cargo run --release -q -p qlab-devnet --bin load 2>/dev/null > run2.txt
$ diff -q run1.txt run2.txt
# (no output — identical)
```

`diff` reports no differences across all four sections. This satisfies bench
discipline #3 (reproduced twice) with a stronger guarantee than the prover-timing
runs: there is no jitter to average out — a byte-difference between runs could
only come from a non-determinism regression (guarded by the `golden_first_draws`
RNG pin and the per-scenario `deterministic_reproduces_identically` tests).

## Key numbers restated (from the identical output)

**§6 spam-flood (S0 default, launch):** governed chain growth = governor-OFF
baseline at every budget (383,027 MB/day @ 0.5× … 7,660,547 @ 10×); attacker cost
= budget × 100 %. Tail 0.5×–1.0× bounded (growth 1.0–1.7×), higher budgets creep.
→ governor is demand-adaptive; fee floor (§5) is the binding control.

**§2 reorg depth (worst over patience bands + 24 seeds):**

| q | 6h | 24h | 30d |
|---|---|---|---|
| 0.10 | 2 | 2 | 5 |
| 0.20 | 9 | 11 | 14 |
| 0.30 | 15 | 18 | 27 |
| 0.40 | 30 | 43 | 118 |
| 0.45 | 71 | 209 | 330 |

→ ~100 blocks covers `q ≤ 0.40` at realistic (≤24 h) stalls; `q → ½` is finality's job.

**§4 jail threshold:** detection lag = `⌈(1−X)·Y⌉` (25 blk–11.4 h across the grid);
false-jail rate 0 for every `(X, Y)` down to 80 % uptime; onset only at 70 %
uptime under `X ≥ 50 %`.

## Verification

Full unfiltered crate suite green (no mode filter):

```
cargo test --release -p qlab-devnet
```

See run 1 for methodology, full tables, findings, and the data-backed candidate
range per `[open]` constant (all decisions design-side).
