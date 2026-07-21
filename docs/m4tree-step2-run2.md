# M4 step 2 — end-to-end tree/root assembly measurement (run 2)

> Second reproduction of run 1 (separate process launches). Protocol, rig, and
> method identical to `m4tree-step2-run1.md` (see it for the full provenance
> block). Numbers ONLY; verdict is the coordinator's.

## Rig / provenance (bench discipline)

- **qumbra-lab rev:** `fbe44d9` (branch `claude/m4-step2-tree`)
- **prover:** Plonky3 0.6.1 (pinned)
- **hardware:** Apple M5 Max, 36 GiB RAM · **OS:** macOS 26.5.2 (25F84)
- **power state:** AC (80%, not charging); no thermal warning
- **method:** as run 1 — release binary directly under `/usr/bin/time -l`, one
  `--lane` per process, foreground bare-metal, serial, no competing tasks.

## Results — run 2

| lane | leaf L (s) | leaf R (s) | interior (s) | whole tree (s) | interior fixed | interior peak footprint | max RSS | swaps |
|---|---|---|---|---|---|---|---|---|
| **b4/q40/g20/fp16/a16** | 2.96 | 3.05 | 45.68 | **53.35** | 0.82 MB | **30.42 GB** (32,666,738,088 B) | 24.40 GB | 0 |
| **b2/q80/g20/fp16/a16** | 3.00 | 3.02 | 4.82 | **12.54** | 1.51 MB | **20.53 GB** (22,044,803,104 B) | 20.70 GB | 0 |

## Reproduction summary (run 1 vs run 2)

| lane | interior peak footprint | Δ | interior prove | whole tree |
|---|---|---|---|---|
| b4 | 30.42 GB (32,665,361,832 → 32,666,738,088 B) | +1.4 MB | 59.23 → 45.68 s (compression noise) | 66.43 → 53.35 s |
| b2 | 20.53 GB (22,039,887,880 → 22,044,803,104 B) | +4.9 MB | 4.83 → 4.82 s (clean, stable) | 12.44 → 12.54 s |

- **Peak footprint reproduced at both lanes** (±1.4 MB b4, ±4.9 MB b2 — grind
  jitter, not swap): b4 = 30.42 GB, b2 = 20.53 GB, matching PR #23's stage-3
  interior gate. The Σfee rider is footprint-free.
- **b4 interior prove time varies (59→46 s)** under compressor engagement — the
  §7.1.4 / PR #23 finding stands (prove time is compression noise at b4/2^19;
  footprint is the demand metric). **b2 is clean and stable (4.83/4.82 s).**
- All four runs (this doc + run 1): **zero swaps**, both hard-assertion consumer
  checks (issue #24 root + 棒 3-3 Σfee) PASSED every run.
- Operating-point note for the coordinator (§7.3, per-level config still open):
  b2/q80 buys ~10 GB footprint headroom and a clean, reproducible ~4.8 s interior
  (12.5 s whole tree) at 1.51 MB vs b4/q40's 0.82 MB — consistent with PR #23's
  flag that b2/q80 may be the better aggregation-lane operating point.
