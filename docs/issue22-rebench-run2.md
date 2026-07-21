# issue #22 (B′) — grind 20→22 prove-time re-bench (run 2)

> Independent reproduction of `docs/issue22-rebench-run1.md` (fresh processes).
> Confirms the size-invariance and RAM-neutrality of the grind bump; prove-time
> differences vs run 1 are parallel-grind PoW jitter (known since M1.6). Run 2's
> whole-tree pass was launched with **no `--lane` flag** to also verify the new
> default resolves to b2 (issue #22 item 2).

## Rig / provenance (bench discipline)

- **qumbra-lab rev:** `628251d` (branch `claude/issue22-config-pass`)
- **prover:** Plonky3 0.6.1 (pinned in `Cargo.lock`)
- **hardware:** Apple M5 Max, 36 GiB RAM
- **OS:** macOS 26.5.2
- **power state:** AC (not charging); no thermal warning
- **method:** as run 1 — release binary directly under `/usr/bin/time -l`, foreground, zero-swap verified.

## Results — run 2

| target | mode / config | prove | verify | fixed size | peak footprint | max RSS | swaps |
|---|---|---|---|---|---|---|---|
| consensus 2×2 bucket | `bucket` b16/q20/g22/fp16/a16 | 1839.2 ms | 15.8 ms | **139721 B (136.4 KB)** | 11.78 GB | 11.90 GB | 0 |
| aggregation leaf | `m4gate` b4/q40/g22/fp16/a16 | 1357 ms | 12.6 ms | **781.8 KB** | 11.78 GB | 11.89 GB | 0 |
| interior (2-child) | `m4interior` two-child/b2/q80/g22 | 7.38 s | — | **1.51 MB** | **19.66 GB** | 18.47 GB | 0 |
| whole tree (default lane) | `m4assembly` (no flag) | 17.45 s (tree) | native ✓ | leaf 781.8 KB / interior 1.51 MB | 21.59 GB | 17.36 GB | 0 |

- **Default-lane check: `m4assembly` with no `--lane` printed `interior lane: **b2/q80/g22/fp16/a16**` — the default flip (item 2) works.**
- whole tree segments: leaf L 3.98 s, leaf R 3.28 s, interior root 6.96 s. issue #24 consumer check + epoch Σfee check both PASSED.
- interior rows 2^19.

## Reproduction summary (run 1 vs run 2)

| target | fixed size (run1 / run2) | peak footprint (run1 / run2) | prove (run1 / run2) |
|---|---|---|---|
| consensus bucket | 139721 B / 139721 B ✓ | 11.78 / 11.78 GB | 1832 / 1839 ms |
| leaf gate | 781.8 / 781.8 KB ✓ | 11.78 / 11.78 GB | 700 / 1357 ms (grind jitter) |
| interior b2/q80 | 1.51 / 1.51 MB ✓ | 19.49 / 19.66 GB (±0.9%) | 9.16 / 7.38 s (grind jitter) |
| whole tree b2 | leaf 781.8 KB / interior 1.51 MB ✓ | 19.95 / 21.59 GB | 17.70 / 17.45 s |

**Sizes reproduced byte-identical across both runs.** Peak footprints reproduced within ≤ 8% (all zero-swap, all far inside the ≤ 32 GB envelope). Prove times vary with parallel-grind jitter, as expected — B′'s cost is prove-time, and it is noisy, exactly as the g22 grind (2^22 PoW) predicts. No size or RAM (>10%) stop-condition tripped.
