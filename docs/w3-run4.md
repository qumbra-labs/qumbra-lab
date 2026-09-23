# W3 stage 2 — shape P measured, run 4 — the reproduction (lab #700, PR #701)

> [中文版](w3-run4-zh.md) · run 3: [`w3-run3.md`](w3-run3.md) · build notes: [`w3-build-notes.md`](w3-build-notes.md)

Same rig, same rev (`20723c9`), same binary, same invocations as `w3-run3.md` (environment block there). Date: 2026-09-22 23:41 +08 (P b4), 23:42 +08 (canary sample 2); lock owner `QUM-182`.

```sh
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape p   --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape p19 --only b4 --power AC   # canary, second sample (inside ./w3-logs/scoped.sh, same lock)
```

## Run 4

| shape | lane | perms (prog/cap) | width | log_height | max deg | prove ms | verify ms | fixed B | postcard B | peak footprint GB | max RSS GB | swaps | real s | user s | sys s | instr retired |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **shape P** | b4/q43/g22/fp16/a16 | 212/341 | 774 | 20 | 4 | **3757.3** | 19.3 | **312,677** | 362,290 | **15.106** | **15.323** | 0 | 16.28 | 157.03 | 26.02 | 2.31e12 |
| shape P | b2/q86/g22/fp16/a16 | — | 774 | 20 | 4 | **NOT MEASURED** — the lane does not exist for a 4-chunk AIR in p3-uni-stark 0.6.1 (`w3-run3.md` §2; pinned by `l2shape_b2_is_not_a_lane_for_a_degree_4_air`) | | | | | | | | | | |
| CANARY: P AIR chain-only @ 2^19 | b4/q43/g22/fp16/a16 | 0/170 | 774 | 19 | 4 | 1743.8 | 17.4 | 300,293 | 297,9xx | 7.389 | 7.679 | 0 | 7.42 | 95.73 | 6.46 | 1.41e12 |

## Comparison with run 3

| row | run 3 | run 4 | Δ | within ±1 %? |
|---|---|---|---|---|
| P b4 peak footprint (GB) | 15.062 | 15.106 | +0.3 % | ✅ |
| P b4 max RSS (GB) | 15.324 | 15.323 | −0.01 % | ✅ |
| P b4 fixed bytes | 312,677 | 312,677 | 0 | ✅ byte-identical |
| P b4 postcard bytes | 362,133 | 362,290 | +0.04 % | varint noise, as at stage 1 |
| P b4 prove (best of 3) | 3.555 s | 3.757 s | +5.7 % | not a gating number; 5× under 20 s either way |
| P b4 verify (best of 3) | 21.5 ms | 19.3 ms | | |
| P b4 `sys` | 40.30 s | 26.02 s | | both above stage 1's 8–12 % of user; instructions retired flat — page-reclaim work at 15 GB, not a contender (run 3 §5) |
| canary footprint (GB) | 7.562 | 7.389 | −2.3 % | the canary is not a gating row (it gates only the 2^20 start: 7.4–7.6 × 2 < 32 ✓); max RSS 7.675 / 7.679 agree to 0.05 % — the stage-1 metric finding again |

**Carried forward (the larger sample each): 15.11 GB peak footprint, 15.32 GB max RSS, at b4/q43/g22 — inside the ≤ 16 GB gate by 5.6 % / 4.2 %; prove 3.56–3.76 s against ≤ 20 s.** The gate is judged at the L2 lane; with b2 unavailable to a degree-4 AIR the L2 lane for shape P is **b4** by default and by measurement, and the margin is the thinnest number W3 has produced. It is a real margin: two samples, both swap-free, reproduced to 0.3 %.

## The scoped test run (stage-1 ruling §4 — one run, after measurement, same rev)

```sh
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- ./w3-logs/scoped.sh
#  (a) cargo test --release -p qlab-bench -- --test-threads=1 l2shape_shape_p_prove_verify_and_tampered_pv_b4 l2shape_b2_is_not_a_lane_for_a_degree_4_air
#  (c) cargo test --release -p qlab-air -p qlab-note --no-fail-fast -- --test-threads=1
#      cargo test --release -p qlab-bench --no-fail-fast -- --test-threads=1 l2 --skip l2shape_shape_p_prove_verify_and_tampered_pv_b4
```

| crate / step | passed | failed | ignored | time |
|---|---|---|---|---|
| `qlab-air` (lib) — in full | **95** (37 narrow + 1 reference + 26 `l2::` + **31 `l2p::`**) | 0 | 0 | 2,539.4 s |
| `qlab-note` (lib) — in full | **39** (35 + 4 `l2note::`) | 0 | 0 | < 0.1 s |
| `qlab-bench` (bin) — `l2` filtered, `--skip l2shape_shape_p_prove_verify_and_tampered_pv_b4` | **5** (`l2shape::` — lanes floor, mock, S roundtrip b4, S tampered-PV b4, the b2 pin) | 0 | 0 | 11.6 s |
| (a) the skipped 15 GB test + the b2 pin, on their own under the same lock | **2** | 0 | 0 | 5.9 s |
| **total** | **141** result lines = **140 distinct tests** (the b2 pin ran in both (a) and (c2)) | **0** | 0 | wall (c1) 2,549 s + (c2) 13 s + (a) 25 s; sampled peak test-binary RSS at 1 Hz: **8.0 GB** (c1), 7.8 GB (c2), **13.8 GB** (a — the P prove; the bench's 15.3 GB is the true peak, 1 Hz under-samples a 4 s prove) |

Reconciled: `qlab-air` 95 = 38 (`main`) + 26 (stage 1) + 31 (stage 2); `qlab-note` 39 = 35 + 4; `qlab-bench` 5 = 6 `l2shape::` tests − 1 skipped (+ run in (a)). Negatives in the log: `FAILED` 0, `panicked at` 0, `^error` 0. The `l2p::` block is ~25 min of the 42 (31 tests, each a 2^20 × 774 `check_all_constraints`; the eight-way negatives eight of them).

- **Workspace suite: NOT RUN — runner offline** (the `verify-graviton` job on #701 has no runner online; stage-0 ruling §6 records this as owed, not waived).
