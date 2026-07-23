# M9-N7 — integration + soak, T0 readiness evidence (run 2, reproduction)

Second independent run of `cargo run --release -p qlab-bench -- n7soak` on the same
rig (`claude/m9-n7` @ `8be2cb5`, Apple M5 Max / 36 GiB, macOS 26.5.2, AC). See
`m9-n7-run1.md` for the full environment table, scenario descriptions, and the
recorded finding.

## Determinism check

Run 1 and Run 2 stdout are **byte-for-byte identical** (excluding the operator-set
`power state` annotation line):

```
diff <(grep -v 'power state' run1) <(grep -v 'power state' run2)   # empty — IDENTICAL
```

The soak is fully deterministic: KeccakPow + seeded `SplitMix64`, no wall-clock and
no RNG entropy anywhere in the driver.

## Scenarios (identical to run 1)

| scenario | nodes | blocks | pass | finalized | detail |
|---|---|---|---|---|---|
| sync-from-genesis under churn | 4 | 7 | ✅ | Some(0) | all 4 nodes on one tip; late joiner Synced |
| adversarial peers | 2 | 0 | ✅ | Some(0) | 5/5 adversarial objects rejected, no crash |
| restart / reorg / partition | 5 | 3 | ✅ | Some(0) | genuine fork; heavier branch adopted; finality-safe; open==replay |
| long-run leak check | 3 | 1000 | ✅ | — | max-mempool = 0 at all samples; tip = 1000 |

## Reproduction

`cargo run --release -p qlab-bench -- n7soak`. Publishable per bench discipline §3
(reproduced twice on the same rig).
