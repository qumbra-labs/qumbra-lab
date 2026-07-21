# M4 step 2 — end-to-end tree/root assembly measurement (run 1)

> Measurement of the whole two-level tree via the `m4assembly` bench mode
> (M4 step 2 棒 1 driver). This document reports numbers ONLY; the per-level
> operating-point call (b4 vs b2) is the coordinator's, per aggregation-rung1
> §7.3 ("per-level config stays open"). Peak footprint follows the §7.1 protocol
> generalised to `phys_footprint` (PR #23's metric finding: under macOS memory
> compression at b4/2^19, max-RSS is non-reproducible; peak footprint is faithful).

## Rig / provenance (bench discipline)

- **qumbra-lab rev:** `fbe44d9` (branch `claude/m4-step2-tree`; 棒 1 driver +
  棒 3-3 Σfee rider; 68/68 unfiltered release suite green, deg ≤ 3 held)
- **prover:** Plonky3 0.6.1 (pinned in `Cargo.lock`)
- **hardware:** Apple M5 Max, 36 GiB RAM
- **OS:** macOS 26.5.2 (build 25F84)
- **power state:** AC (80%, not charging); no thermal warning
- **method:** release binary run DIRECTLY under `/usr/bin/time -l` (no `cargo`
  wrapper, no output pipe), one `--lane` per process, foreground bare-metal,
  strictly serial (no competing memory tasks; largest non-bench process ~0.46 GB).
  The whole-tree wall time is one process: 2 leaves proved serially (each
  native-verified then dropped) → interior proved → full native verification
  chain (both leaves + interior root) → issue #24 `root == keccak-merge(opvs)`
  and 棒 3-3 `Σfee == fee(childL)+fee(childR)` consumer checks (both hard
  assertions PASSED). Peak footprint attributes to the interior segment (leaves
  freed first). Reproduction = run 2 (separate process launches).

## Results — run 1

| lane | leaf L (s) | leaf R (s) | interior (s) | whole tree (s) | interior fixed | interior peak footprint | max RSS | swaps |
|---|---|---|---|---|---|---|---|---|
| **b4/q40/g20/fp16/a16** | 2.81 | 2.75 | 59.23 | **66.43** | 0.82 MB | **30.42 GB** (32,665,361,832 B) | 22.88 GB | 0 |
| **b2/q80/g20/fp16/a16** | 2.93 | 2.97 | 4.83 | **12.44** | 1.51 MB | **20.53 GB** (22,039,887,880 B) | 20.70 GB | 0 |

- Leaf segments (both lanes commit leaves at the fixed b4/q40 aggregation config)
  include M3 generation + trace build + prove + native verify; ~2.8–3.0 s each.
  Leaf fixed proof size: 781.8 KB (both children; the two are DISTINCT M3
  witnesses — different caps + inner PVs).
- Interior rows: 524288 (2^19), both lanes.
- **b4:** the macOS compressor engages (footprint 30.42 GB on the 36 GiB rig) →
  interior prove time (59.23 s) is compression-inflated (clean b4 ≈ 13–15 s per
  PR #23), and max-RSS (22.88 GB) < footprint. Peak footprint is the faithful,
  reproducible demand metric.
- **b2:** no compression (footprint 20.53 GB < RAM) → clean interior prove
  4.83 s, max-RSS ≈ footprint. The whole tree (2 leaf + 1 interior) is 12.44 s.
- **Both footprints match PR #23's stage-3 interior gate exactly (30.42 / 20.53
  GB)** — the 棒 3-3 Σfee rider adds negligible cells (+4 public values, one
  degree-1 constraint), so it is footprint-free at both lanes.
- Verification chain: PASSED (both leaves + interior root native-verify; issue
  #24 consumer check PASSED; Σfee consumer check PASSED, Σfee = [973218759,0,0,0]
  Monty-scaled). Zero swaps / no pageouts → §7.1-valid.
