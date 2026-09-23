# W3 stage 2 — shape P measured, run 3 (lab #700, PR #701)

> [中文版](w3-run3-zh.md) · reproduction: [`w3-run4.md`](w3-run4.md) · stage 1: [`w3-run1.md`](w3-run1.md) / [`w3-run2.md`](w3-run2.md) · build notes: [`w3-build-notes.md`](w3-build-notes.md)

- hardware: Apple M5 Max, 36 GiB RAM (18 cores)
- OS: macOS 27.0
- qumbra-lab rev: **`20723c9`** (branch `claude/w3-l2-shapes`; the bench binary was built at this rev — the two commits after it touch only `l2shape.rs`'s tests and this doc)
- prover: Plonky3 0.6.1 (`p3-uni-stark 0.6.1`, pinned in `Cargo.lock`)
- power state: AC, no thermal pressure observed; **machine shared** — active + wired ≈ 13.2 GB of other residents at start (vm_stat; stage 1 ran at 16.3)
- date: 2026-09-22, 23:38–23:41 +08 (run 3); lock owner `QUM-182`
- AIR: `qlab_air::l2p::L2ShapePAir` — **774 columns** × 3072 rows/perm, 40 periodic columns, **PV_LEN 112**, max constraint degree **4**, **4 quotient chunks**, **212 perms in a 341-perm height (2^20)** — all read off the matrix / Plonky3's symbolic evaluation by the bench at start-up and by `l2p_trace_width_is_read_off_the_matrix` / `l2p_quotient_degree_matches_the_l1`
- per cell: prove / verify = best of 3 in-process runs; proof bytes = postcard AND bincode-fixed (the wire proxy); peak `phys_footprint` and max RSS from `/usr/bin/time -l` wrapping the **release binary directly**, one shape × one lane per process, inside `scripts/rig run`; swaps asserted 0 on every row

## Invocations (verbatim; `./w3-logs/measure.sh <tag> <shape> <lane>` is the wrapper)

```sh
# canary (#700): the shape-P AIR chain-only at 2^19 — same 774 columns, half the rows (the P program does not fit 2^19)
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape p19 --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape p19 --only b2 --power AC
# canary at b4: 7.56 GB × 2 = 15.1 GB < 32 GB → the 2^20 run may start
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape p   --only b4 --power AC
# control for the b2 failure: shape S (2^19, degree 4) at b2
QUMBRA_RIG_OWNER=QUM-182 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape s   --only b2 --power AC
```

`--only b4` selects `b4/q43/g22/fp16/a16` (the shipping leaf point, `m4treerec::AGG_CFG`); `--only b2` selects `b2/q86/g22/fp16/a16` (the interior lane's ruled point, `m4interior`; `l2shape::B2_CFG`). b8 and b16 were **not run** for shape P (2^20 × 774 at b8 projects ≈ 30 GB — the heavy-lane deferral of the stage-0 ruling §5.3 stands).

## Run 3

| shape | lane | perms (prog/cap) | width | log_height | max deg | prove ms | verify ms | fixed B | postcard B | peak footprint GB | max RSS GB | swaps | real s | user s | sys s | instr retired |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **shape P** | b4/q43/g22/fp16/a16 | 212/341 | 774 | 20 | 4 | **3555.2** | 21.5 | **312,677** | 362,133 | **15.062** | **15.324** | 0 | 19.20 | 156.81 | 40.30 | 2.37e12 |
| shape P | b2/q86/g22/fp16/a16 | 212/341 | 774 | 20 | 4 | — | — | — | — | — | — | — | — | — | — | **NOT RUN** — the lane does not exist for this AIR (below) |
| CANARY: P AIR chain-only @ 2^19 | b4/q43/g22/fp16/a16 | 0/170 | 774 | 19 | 4 | 1691.6 | 19.6 | 300,293 | 298,040 | 7.562 | 7.675 | 0 | 7.89 | 87.22 | 9.70 | 1.36e12 |
| CANARY: P AIR chain-only @ 2^19 | b2/q86/g22/fp16/a16 | 0/170 | 774 | 19 | 4 | **FAILED** (prove ran; `verify` → `OodEvaluationMismatch`) | | | | 10.521 | 10.452 | 0 | 12.12 | 99.53 | 22.01 | 1.21e12 |
| control: shape S @ 2^19 | b2/q86/g22/fp16/a16 | 120/170 | 702 | 19 | 4 | **FAILED** (same rejection) | | | | 9.364 | 9.625 | 0 | 9.79 | 119.73 | 5.22 | 1.39e12 |

CANARY rows price width × height only and gate nothing but the 2^20 start (#700's rule). "perms prog/cap" = program perms including the warm-up slot / perms the height holds.

## What the numbers say

1. **Shape P at b4/q43: 15.06 GB peak footprint (15.32 GB max RSS), 3.56 s prove, 312,677 B fixed-width, zero swap — INSIDE the gate (≤ 16 GB, ≤ 20 s).** The margin is thin on the number that decides: **5.9 % on the footprint, 4.2 % on max RSS** against 16 GB; ample on time (5.6× under). Stage 1's projection from the measured 2^20 twin (14.11 GB × 790/702 = 15.6–15.9 GB) came in **0.5–0.8 GB high**, because the width came in at 774, not ~790 (no new equality bank — every cross-row binding shape P needs rides an existing bank's idle span; `w3-build-notes.md` §Stage 2). Scaling the twin by the measured width instead, 14.11 × 774/702 = 15.56 GB, is **3 % above** the measurement — the LDE-law excess stage 1 found (~15 %) is unchanged (2^20 × 774 × 16 B = 13.0 GB projected → 15.06 measured, +16 %).
2. 🔴 **The b2 lane is not available to this circuit family**, and the stage-1 ruling's "b2 is a live option, not a fallback" premise does not hold at degree 4. With 4 quotient chunks and `log_blowup = 1`, the prover's quotient domain (4N) is larger than the committed LDE (2N): `p3-uni-stark 0.6.1`'s `get_evaluations_on_domain` falls back to re-extending the trace through a coset iDFT/DFT (the extra RAM the canary shows — 10.5 GB at 2^19 b2 against 7.6 GB at b4), the prover completes, and **the verifier rejects the proof with `OodEvaluationMismatch`** — for shape P's AIR and, as the control shows, for **shape S's** too (same degree). The interior lane's `b2/q86` works because that AIR has **2 quotient chunks** (degree ≤ 3). Pinned by `l2shape_b2_is_not_a_lane_for_a_degree_4_air` so a prover bump that lifts the restriction is noticed. The b2 row is therefore **NOT MEASURED — lane structurally unavailable**, not skipped. The way to a b2 lane is a **degree-3 variant** of the AIR: materialize the 21 five-bit selectors' `pair·top` (8 columns), `EG3[1]`'s `bnd·SE` (1), the 16 comparison transitions' `[x = y]` products (8), the two `ALW`-gated bank-1 legs (2) and the three `gperm|bnd·sel·ep` gates (2) — **≈ 21 columns → ~795, and the b2 LDE then projects to 2^20 × 795 × 8 B × 1.16 ≈ 7.7 GB** [derived, not measured]. That changes the degree the ruling froze ("degree stays 4 or it is a stop-point"), so it is **priced here and not built**; the coordinator rules whether the second lane is worth a degree change.
3. **Bytes**: 312,677 B fixed at 2^20 × 774 vs shape S's 297,989 B at 2^20 × 702 (+4.9 % for +10 % width) and 285,605 B at 2^19 — proof size follows `log_height` and width, as stage 1 found; the book's ~950 KB pre-registration for P is retired along with S's.
4. **Prove time** 3.56 s (run 3) / 3.76 s (run 4) against stage 1's re-projection of ≈ 3.6 s — on the line. Verify 19–22 ms.
5. **`sys` is elevated on both P rows** (40 s and 26 s against 157 s user — 26 % and 17 %; stage 1's rows sat at 8–12 %) with instructions retired flat (2.37e12 / 2.31e12). The contamination tell is *sys several-fold with instructions flat*; 1.5× between two runs of the same binary at 15 GB is page-reclaim work (6.2 M / 4.6 M page reclaims on the two rows, against 1.7 M on the 7.6 GB canary) rather than a rig contender (the lock was held by `QUM-182` throughout, `vm_stat` read 13.2 GB of other residents). Both prove times are reported; neither is discarded; the smaller `sys` row (run 4) is the cleaner sample and it is the slower prove — the ordering is not what contamination produces.
6. **Zero swap on every row**, including the two failed b2 rows.

## Reproduction status (±1 % rule, #700) — see `w3-run4.md`

| row | run 3 | run 4 | within ±1 %? |
|---|---|---|---|
| P b4 peak footprint | 15.062 | 15.106 | ✅ 0.3 % |
| P b4 max RSS | 15.324 | 15.323 | ✅ 0.01 % |
| P b4 fixed bytes | 312,677 | 312,677 | ✅ byte-identical |
| P b4 prove (best of 3) | 3.555 s | 3.757 s | 5.7 % spread — time is not a gating number under the ±1 % rule; both under 20 s by 5× |
| canary P-AIR @ 2^19 b4 footprint | 7.562 | see run 4 | |

**The demand figure carried forward: 15.11 GB peak footprint / 15.32 GB max RSS at b4/q43 (the larger of the two samples each), against 16 GB — a 5.6 % / 4.2 % margin.** Stage 1's metric finding holds at this size: max RSS is the reproducible number (15.324 / 15.323) and the footprint moves at the 0.3 % level.

## The scoped test run (stage-1 ruling §4)

See `w3-run4.md` §"The scoped test run" — one run, after both measurement runs, on the same rev.
