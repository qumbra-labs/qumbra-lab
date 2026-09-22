# W3 stage 1 — shape S measured, run 1 (lab #700, PR #701)

> [中文版](w3-run1-zh.md) · reproduction: [`w3-run2.md`](w3-run2.md) · build notes: [`w3-build-notes.md`](w3-build-notes.md)

- hardware: Apple M5 Max, 36 GiB RAM (18 cores)
- OS: macOS 27.0
- qumbra-lab rev: `8a20234` (branch `claude/w3-l2-shapes`, tree CLEAN per `scripts/rig`'s banner on every run)
- prover: Plonky3 0.6.1 (`p3-uni-stark 0.6.1`, pinned in `Cargo.lock`)
- power state: AC, battery 80 % not charging, no thermal pressure observed; **machine shared** — active + wired ≈ 16.3 GB of other residents at start (vm_stat)
- date: 2026-09-22, 18:43–18:47 +08 (run 1); lock owner `QUM-181`
- AIR: `qlab_air::l2::L2ShapeSAir` — **702 columns** × 3072 rows/perm, 40 periodic columns, **PV_LEN 100**, max constraint degree **4**, **4 quotient chunks** (all read off the matrix / Plonky3's symbolic evaluation by the bench at start-up and by `l2_trace_width_is_read_off_the_matrix` / `l2_quotient_degree_matches_the_l1`)
- per cell: prove / verify = best of 3 in-process runs; proof bytes = postcard AND bincode-fixed (the wire proxy); peak `phys_footprint` and max RSS from `/usr/bin/time -l` wrapping the **release binary directly**, one shape × one lane per process, inside `scripts/rig run`; swaps asserted 0 on every row

## Invocations (verbatim; `./w3-logs/measure.sh <tag> <shape> <lane>` is the wrapper)

```sh
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape s       --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape mock118 --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape s       --only b8 --power AC
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape mock118 --only b8 --power AC
# canary (#700): 2^19 b4 peak footprint 6.78 GB × 2 = 13.6 GB < 32 GB → the 2^20 lanes may start
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape s20     --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape mock240 --only b4 --power AC
```

`--only b4` selects `b4/q43/g22/fp16/a16` (the shipping leaf point, `m4treerec::AGG_CFG`); `--only b8` selects `b8/q29/g22/fp16/a16`. The b16 lane and the 2^20 b8 lanes were **not run** (stage-0 ruling §5.3: heavy lanes deferred).

## Run 1

| shape | lane | perms (prog/cap) | width | log_height | max deg | prove ms | verify ms | fixed B | postcard B | peak footprint GB | max RSS GB | swaps | real s | user s | sys s | instr retired |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **shape S** | b4/q43/g22/fp16/a16 | 120/170 | 702 | 19 | 4 | **1516.8** | 20.6 | **285,605** | 331,718 | **6.782** | 7.067 | 0 | 5.90 | 61.61 | 6.62 | 9.77e11 |
| **shape S** | b8/q29/g22/fp16/a16 | 120/170 | 702 | 19 | 4 | **2582.7** | 18.3 | **206,221** | 239,801 | **13.756** | 13.755 | 0 | 8.91 | 102.84 | 11.87 | 1.55e12 |
| shape S @ 2^20 (P-height proxy) | b4/q43/g22/fp16/a16 | 120/341 | 702 | 20 | 4 | 3192.2 | 23.1 | 297,989 | 346,567 | 14.111 | 14.107 | 0 | 11.50 | 130.39 | 10.38 | 1.89e12 |
| MOCK 118 @ 2^19 | b4/q43/g22/fp16/a16 | 118/170 | 702 | 19 | 4 | 1558.4 | 21.2 | 285,605 | 328,697 | 6.782 | 7.067 | 0 | 5.67 | 61.88 | 6.65 | 9.54e11 |
| MOCK 118 @ 2^19 | b8/q29/g22/fp16/a16 | 118/170 | 702 | 19 | 4 | 2476.4 | 17.7 | 206,221 | 237,535 | 13.477 | 13.758 | 0 | 8.50 | 99.13 | 11.41 | 1.44e12 |
| MOCK 118-prog @ 2^20 ("240") | b4/q43/g22/fp16/a16 | 118/341 | 702 | 20 | 4 | 3213.4 | 23.6 | 297,989 | 343,567 | 13.562 | 14.110 | 0 | 11.53 | 130.84 | 9.96 | 1.85e12 |

MOCK rows are labelled MOCK and gate nothing (#700 stage 0). "perms prog/cap" = program perms including the warm-up slot / perms the height holds.

## What the numbers say

1. **Shape S at b4: 6.78 GB peak footprint, 1.52 s prove, 285,605 B fixed-width.** Against the book's pre-registration (~5 GB / ~470 KB) the RAM is +36 % and the bytes are −39 %: the book scaled bytes linearly with rows, but proof size grows with `log_height` and width (the query-path length), not with rows — 278.9 KB fixed vs the M3 b4 point's 236.4 KB at 617 × 2^18 is +18 %. Against the LDE-law projection posted at stage 0 (5.9 GB) the footprint is **+15 %**; the same excess appears at b8 (13.76 vs 11.8 projected, +17 %) and at 2^20 (13.6–14.1 vs 11.8, +15–20 %). **The LDE law under-projects this geometry by ~15 %, and the excess is not visible at the M3 point** (2.59 projected / 2.6 measured). Carry that factor into every shape-P projection below.
2. **The mock reproduces shape S at the same height to within 2 %** on every column — as it must, since width and height are what the prover prices; the 2 perms and the registry roles are noise. The mock's job (pricing 2^20 before the real circuit) is discharged: at 2^20 b4 the machine needs **13.6–14.1 GB**.
3. **Shape P at b4, re-projected from the measured 2^20 twin** (stage-0 ruling §3 re-registered 13–14 GB; this replaces it): `s20 b4` measured 13.9–14.1 GB at width 702; shape P is projected at ~790 columns (`w3-build-notes.md` §census, gadget (a)); scaling footprint linearly with width (the only scaling the LDE law and the M3 → S delta support), **P b4 ≈ 13.9 × 790/702 = 15.6 GB to 14.1 × 790/702 = 15.9 GB against the 16 GB gate — a 1–3 % margin, not 15 %.** Prove time: s20 b4 3.19 s → P ≈ 3.6 s (+12 % width, same height) against 20 s — ample. The RAM side of the envelope is the whole of stage 2's risk, and **b2 is the lever** (halves the LDE: ~8 GB class), not tree depth. Not a STOP: nothing is out yet, and a ≤ 2× miss has a named tuning round.
4. **b8 costs 2.0× the RAM of b4 for −28 % bytes** (13.76 vs 6.78 GB; 206 KB vs 286 KB) and +70 % prove time. On the design's own criterion (§2.5: the L2 lane is chosen for prover RAM, not bytes — its proofs are aggregated and pruned) **b4 is the lane**, and this is the first measurement that says so with both numbers in hand.
5. **Verify 18–24 ms**; postcard bytes carry an instance-dependent ±0.05 % (varint), fixed-width bytes are byte-identical across runs and shapes at equal geometry (285,605 / 206,221 / 297,989 B).
6. **Zero swap on every row**, and `sys` sits at 10–12 % of `user` on all six run-1 rows (the contamination tell — `sys` inflated several-fold with instructions retired flat — is absent in run 1; see `w3-run2.md` for two rows where it is not).

## Reproduction status (±1 % rule, #700) — see `w3-run2.md` for the full comparison

| row | run 1 | run 2 | third / fourth | within ±1 %? |
|---|---|---|---|---|
| S b4 footprint | 6.782 | 6.797 | — | ✅ 0.2 % |
| S b8 footprint | 13.756 | 13.479 | run 3: **13.758** | ✅ runs 1 & 3 (0.02 %); run 2 sits on the mock's value 13.48 |
| s20 b4 footprint | 14.111 | 13.895 | run 3: 13.562, run 4: **13.892** | ✅ runs 2 & 4 (0.02 %); the four samples take three discrete values (13.56 / 13.89 / 14.11); **max RSS 14.107–14.111 GB on all four** |
| mock118 b4 / b8, mock240 b4 footprint | 6.782 / 13.477 / 13.562 | 6.783 / 13.477 / 13.563 | — | ✅ to the megabyte |

The demand figure carried forward for the 2^20 geometry is the **maximum observed, 14.11 GB** (footprint run 1; max RSS on all four samples). Metric finding, recorded for the rig doc: at this size the compressor never engages (zero swap, `sys` flat), so **max RSS is the reproducible metric here and the footprint is the one that takes discrete values** — the opposite of aggregation-rung1 §7.1's finding at the 30 GB class, where the compressor made RSS the noisy one. Both are reported on every row; the larger is the number.

## The b8 lane, re-derivable

`b8/q29/g22/fp16/a16`. Conjectured bits = `q · β(ρ) + g` under the 2197-corrected accounting; β from the three ruled lanes (`fri-soundness-accounting-2026-07.md` §6 table, B″ targets reproduced exactly): **β(b16) = (96.9 − 22)/20 = 3.745**, **β(b4) = (96.1 − 22)/40 = 1.853**, **β(b2) = (94.8 − 22)/80 = 0.910** bits/query. `1 − δ* = 2^−β` gives δ* = 0.925 / 0.723 / 0.468, i.e. 0.012 / 0.027 / 0.032 below capacity `1 − ρ`. Bracketing b8's gap (capacity 0.875) between b4's and b16's: δ* ∈ [0.848, 0.863], **β(b8) ∈ [2.72, 2.87]**; `q ≥ (100 − 22)/β ∈ [27.2, 28.7]` → **q29** (100.9 at the conservative end; 105.2 at the other). The exact Cor. 4.5 optimisation at ρ = 1/8 was not run. Capacity proxy asserted by `make_config_with`: 29 × 3 + 22 = 109.

## The scoped test run (stage-0 ruling §6 — the one local run permitted; the runner is offline)

```sh
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- ./w3-logs/scoped-tests.sh
#   = cargo test --release -p qlab-air -p qlab-note -p qlab-bench --no-fail-fast -- --test-threads=1
```

| crate | passed | failed | ignored | time |
|---|---|---|---|---|
| `qlab-air` (lib) | **64** (37 narrow + 1 reference + **26 `l2::`**) | 0 | 0 | 1,623.8 s |
| `qlab-bench` (bin) | 113 (110 + 3 `l2shape::`) | **1** — `l2shape_mock_program_is_the_padded_l1_shape`, `left: 117, right: 118` | 0 | 948.8 s |
| `qlab-note` (lib) | **39** (35 + **4 `l2note::`**) | 0 | 0 | < 0.1 s |
| doc-tests (3 sets) | 0 | 0 | 0 | — |
| **total** | **216** | **1** | 0 | wall **2,604 s** (43.4 min incl. the cold release build of the three crates' deps); peak test-binary RSS **16.7 GB** sampled at 1 Hz (`ps rss` over `target/release/deps/qlab_*`) |

- The one failure was **test arithmetic**: the mock test counted 118 non-dummy roles where the program has 118 perms *including* the warm-up dummy (117 non-dummy — the same convention `SHAPE_S_PERMS = 120 = 1 + 119` uses). Fixed in `8a20234`; the fixed test re-run alone (`cargo test --release -p qlab-bench l2shape_mock_program_is_the_padded_l1_shape`, under the lock, a strict subset of the permitted set): **1 passed, 6.2 s**.
- The **16.7 GB peak is not the L2 tests'** — it is `qlab-bench`'s pre-existing prove-carrying tests (`m6devnet`/`n7soak` drive real M3 proofs); `l2shape_shape_s_prove_verify_roundtrip_b4` (a real 2^19 × 702 prove at b4/q43 through `p3_uni_stark::prove`/`verify`) is the ~7 GB class this doc measures. Declared because the ruling expected single-digit GB: the crate carries more than its L2 tests.
- **The 26 `l2::` tests took ~27 min of the 43** — every negative iterates 16 selector assignments × a 2^19 `check_all_constraints`. After this run the helper was cut to the 8 `(o1a, o2a, f1)` assignments at the witness's honest `q` (`8a20234`), because `q`'s two constraints read only the captured `A₁`/`A₂` and are refused on their own (`l2_neg_q_lie_is_unsat_both_ways`). **The 8-way form is a strict subset of the assertions the 16-way run executed and has not itself been executed** — declared, not hidden; it roughly halves the crate's CI time.
- **Workspace suite: NOT RUN — runner offline** (the `verify-graviton` job for #701 has been queued since 08:25Z with no runner online; stage-0 ruling §6 records this as owed, not waived).
