# qumbra-lab M4 step 0b(ii): the calibration gate — verifier gate rectangle (run 2)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 5af1d28 (gate-exit worktree, committed on claude/m4-gate-exit)
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, idle rig (record thermal manually)
- rectangle: **3,626 cols x 2^16, 2,382 lane perms**; identical shape to run 1
  (fresh process, second measurement per bench discipline).

| lane config | rows | prove ms | verify ms | postcard KB | fixed KB |
|---|---|---|---|---|---|
| b4/q40/g20/fp16/a16 | 65536 | 677 | 13.5 | 938.7 | 779.6 |
| b16/q20/g20/fp16/a16 | 65536 | 2149 | 8.1 | 546.7 | 453.6 |

## Peak RSS (`/usr/bin/time -l` with `--only`, fresh processes)

| lane config | peak RSS |
|---|---|
| b4/q40/g20/fp16/a16 | 11.89 GB (11,889,475,584 B) |
| b16/q20/g20/fp16/a16 | 17.28 GB (17,284,366,336 B) |

## Reproducibility (run 1 vs run 2)

| metric | b4 run1 | b4 run2 | b16 run1 | b16 run2 |
|---|---|---|---|---|
| prove ms | 667 | 677 | 2180 | 2149 |
| fixed KB | 779.6 | 779.6 | 453.6 | 453.6 |
| peak RSS (GB) | 11.89 | 11.89 | 16.31 | 17.28 |

Prove time reproduces within ±1.5% (b4) / ±1.5% (b16); proof size is bit-exact.
Peak RSS is stable at b4 (11.89 GB, identical to 6 significant figures) and
varies ~6% at b16 (16.3–17.3 GB) — the known LDE-buffer + parallel-grind jitter
(m1.6 precedent). **Both configs remain far inside ≤ 10 s / ≤ 32 GB on both
runs.**

## Calibration verdict (confirmed, reproduced twice)

**PASS.** The leaf verifier fits the aggregation-rung1 §6 envelope with 4.6–15×
time margin and 1.9–2.7× RAM margin. Worst observed point (b16 run 2): 2.15 s /
17.28 GB — still 4.6× under the time budget and 1.9× under the RAM budget.
→ M4 step 1 (tree prototype) is unblocked; no design-doc re-open needed
(the leaf is well inside, not "outside by ≥ 2×").
