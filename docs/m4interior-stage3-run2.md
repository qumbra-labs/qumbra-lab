# M4 step 1 stage 3 — interior two-child peak-RSS measurement (run 2, reproduction)

> Second pass, same rig, fresh processes — the bench-discipline reproduction of
> [run 1](m4interior-stage3-run1.md). Numbers only; §7.3 verdict is the
> coordinator's.

## Rig / provenance

Identical to run 1: qumbra-lab `b6f7246`, Plonky3 0.6.1 (pinned), Apple M5 Max /
36 GiB, macOS 26.5.2, AC (80% batt, not charging), no thermal warning. Release
binary directly under `/usr/bin/time -l`, one `--only` row per process. Free
memory checked before each run (`vm_stat`): 23.8 GB (before b4), 27.4 GB (before
b2 r1), 26.9 GB (before b2 r2).

## Run-2 numbers

| row | height | prove s | **max RSS** | **peak footprint** | swaps | block in/out | sys s |
|---|---|---|---|---|---|---|---|
| single-child/b4/q40 (canary) | 2^18 | 6.30 | 15.22 GB (16,344,760,320) | 20.48 GB (21,989,162,872) | 0 | 0 / 0 | — |
| two-child/b4/q40 | 2^19 | 42.74 | 23.38 GB (25,103,351,808) | 30.42 GB (32,665,771,432) | 0 | 0 / 0 | 118.6 |
| two-child/b2/q80 | 2^19 | 4.71 | 20.70 GB (22,226,124,800) | 20.53 GB (22,041,444,360) | 0 | 0 / 0 | 15.4 |

- proof size (fixed): single b4 0.81 MB, two-child b4 0.82 MB, two-child b2 1.51 MB.
- **no run had nonzero swap-ins/pageouts** — none disqualified by §7.1.4.

## Reproduction verdict (run 1 vs run 2)

| row | metric | run 1 | run 2 | Δ | reproduces? |
|---|---|---|---|---|---|
| single-child/b4 (2^18) | max RSS | 15.22 GB | 15.22 GB | 4.7 MB | ✅ |
| two-child/b4 (2^19) | **max RSS** | 16.42 GB | 23.38 GB | 6.96 GB | ❌ compression artifact |
| two-child/b4 (2^19) | **peak footprint** | 30.42 GB | 30.42 GB | 1.3 MB | ✅ (the faithful b4 number) |
| two-child/b2 (2^19) | max RSS | 20.70 GB | 20.70 GB | 0.75 MB | ✅ |
| two-child/b2 (2^19) | peak footprint | 20.53 GB | 20.53 GB | 5.6 MB | ✅ |

- **two-child b4 max RSS does NOT reproduce** (16.42 ↔ 23.38 GB) — the run with
  more free memory at launch (run 2, 23.8 GB free) compressed less → higher RSS,
  faster prove (42.7 s); run 1 (less free) compressed harder → lower RSS, 166 s.
  Both are the same underlying job. Per §7.1.4 this max-RSS number is
  disqualified as noise; the faithful, reproduced b4 demand is **peak footprint
  = 30.42 GB**.
- **two-child b2** reproduces on BOTH metrics to ~1 MB (20.70 / 20.53 GB) — the
  clean, wall-safe headline.
- canary max RSS reproduces exactly (15.22 GB); its footprint is the only noisy
  no-pressure figure (16.53 → 20.48 GB), which does not matter since max RSS is
  the faithful metric when the compressor is idle.

## Headline (reproduced-twice, publishable per bench-discipline #3)

| interior config (2^19, distinct children, merged root) | peak RSS | prove | note |
|---|---|---|---|
| **b4/q40/g20/fp16/a16** | **30.42 GB peak footprint** (max RSS = compression artifact, 16.4–23.4 GB) | 42.7–166 s (compression noise; ~13–15 s clean) | thrashes compressor on 36 GiB; no disk swap |
| **b2/q80/g20/fp16/a16** | **20.70 GB max RSS = 20.53 GB footprint** | 4.7–4.9 s | clean, reproduces to ~1 MB |

Compare to aggregation-rung1 §6/§7.3 envelope **≤ 30 s / ≤ 32 GB**: reported as
facts above; the pre-registered §7.3 verdict (keyed on two-child b4 peak RSS) is
the coordinator's table lookup, not made here.
