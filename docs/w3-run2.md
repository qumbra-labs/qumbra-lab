# W3 stage 1 — shape S measured, run 2 (the reproduction) (lab #700, PR #701)

> [中文版](w3-run2-zh.md) · run 1: [`w3-run1.md`](w3-run1.md) (environment, invocations, derivations, the test run) · build notes: [`w3-build-notes.md`](w3-build-notes.md)

Same rig, same rev `8a20234`, same binary (`target/release/qlab-bench`, built 18:41 +08), same invocations as run 1, one shape × one lane per process under `scripts/rig run` with `/usr/bin/time -l` on the release binary; 2026-09-22 18:44–18:45 +08, immediately after run 1's six rows, lock owner `QUM-181`. Third and fourth samples (18:46–18:47) were taken for the two rows whose footprints fell outside ±1 %.

## Run 2

| shape | lane | perms (prog/cap) | width | log_height | max deg | prove ms | verify ms | fixed B | postcard B | peak footprint GB | max RSS GB | swaps | real s | user s | sys s | instr retired |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **shape S** | b4/q43/g22/fp16/a16 | 120/170 | 702 | 19 | 4 | 1765.5 | 21.0 | **285,605** | 331,741 | **6.797** | 7.082 | 0 | 6.64 | 73.44 | 7.04 | 1.03e12 |
| **shape S** | b8/q29/g22/fp16/a16 | 120/170 | 702 | 19 | 4 | 3182.6 | 21.9 | **206,221** | 239,639 | 13.479 | 13.761 | 0 | 10.88 | 126.46 | 12.85 | 1.58e12 |
| shape S @ 2^20 (P-height proxy) | b4/q43/g22/fp16/a16 | 120/341 | 702 | 20 | 4 | 4223.7 | 27.6 | 297,989 | 346,723 | 13.895 | 14.107 | 0 | 17.48 | 169.92 | **21.93** | 2.00e12 |
| MOCK 118 @ 2^19 | b4/q43/g22/fp16/a16 | 118/170 | 702 | 19 | 4 | 1854.4 | 22.2 | 285,605 | 328,697 | 6.783 | 7.067 | 0 | 6.96 | 77.19 | 7.84 | 1.04e12 |
| MOCK 118 @ 2^19 | b8/q29/g22/fp16/a16 | 118/170 | 702 | 19 | 4 | 3058.5 | 21.1 | 206,221 | 237,535 | 13.477 | 13.758 | 0 | 10.27 | 118.63 | 13.08 | 1.44e12 |
| MOCK 118-prog @ 2^20 ("240") | b4/q43/g22/fp16/a16 | 118/341 | 702 | 20 | 4 | 4156.8 | 28.4 | 297,989 | 343,567 | 13.563 | 14.114 | 0 | 14.62 | 166.79 | 11.86 | 1.85e12 |

## Third and fourth samples

| tag | shape | lane | prove ms | verify ms | fixed B | peak footprint GB | max RSS GB | swaps | real s | user s | sys s | instr retired |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| run 3 | shape S | b8 | 2895.8 | 15.8 | 206,221 | **13.758** | 13.738 | 0 | 10.54 | 121.11 | 13.56 | 1.60e12 |
| run 3 | s20 | b4 | 3783.8 | 26.5 | 297,989 | 13.562 | 14.111 | 0 | 13.57 | 156.69 | 11.91 | 1.97e12 |
| run 4 | s20 | b4 | 3982.9 | 19.7 | 297,989 | **13.892** | 13.885 | 0 | 17.02 | 138.40 | **28.55** | 1.96e12 |

## Run 1 vs run 2 — the ±1 % rule, row by row

| row | metric | run 1 | run 2 | Δ | verdict |
|---|---|---|---|---|---|
| S b4 | footprint GB | 6.782 | 6.797 | +0.2 % | ✅ |
| S b4 | fixed B | 285,605 | 285,605 | 0 | ✅ byte-identical |
| S b8 | footprint GB | 13.756 | 13.479 | −2.0 % | ❌ → run 3 **13.758** agrees with run 1 to 0.02 %; run 2's value is the mock's (13.477/13.477) |
| S b8 | fixed B | 206,221 | 206,221 | 0 | ✅ |
| s20 b4 | footprint GB | 14.111 | 13.895 | −1.5 % | ❌ → run 3 13.562, run 4 **13.892** agrees with run 2 to 0.02 %; **max RSS 14.107 / 14.107 / 14.111 / 13.885** |
| s20 b4 | fixed B | 297,989 | 297,989 | 0 | ✅ |
| mock118 b4 | footprint GB | 6.782 | 6.783 | +0.01 % | ✅ |
| mock118 b8 | footprint GB | 13.477 | 13.477 | 0 | ✅ |
| mock240 b4 | footprint GB | 13.562 | 13.563 | +0.01 % | ✅ |
| every row | swaps | 0 | 0 | — | ✅ |

**Reading.** Bytes are byte-identical everywhere (a fixed-width wire is a function of geometry and config only). Footprints reproduce to the megabyte on the mock rows and on S b4, and take **discrete values** on S b8 (13.48 / 13.76) and s20 b4 (13.56 / 13.89 / 14.11) — steps of ~0.22–0.28 GB, which is the size of a transient buffer coexisting or not with the peak, not drift. The number carried is the **maximum observed per geometry**: **S b4 6.80 GB, S b8 13.76 GB, 2^20 b4 14.11 GB** (the last also the max RSS on 4/4 s20 samples and 2/2 mock240 samples). This is conservative and it is what the P projection in `w3-run1.md` §3 uses.

**Prove times: run 2 is 15–30 % slower than run 1 on every row** (S b4 1766 vs 1517 ms; S b8 3183 vs 2583; s20 4224 vs 3192) at nearly flat instructions retired (+2–6 %), and two rows carry the **contamination tell**: s20 b4 run 2 `sys` 21.9 s and run 4 `sys` 28.6 s against 10–12 s on the other samples, instructions retired flat (1.96–2.00e12 on all four). Something else was drawing on the shared machine during those windows (other residents ≈ 16 GB; no rig contender — `scripts/rig` was held by this owner throughout). Per CLAUDE.md the contaminated **times** are discarded, not caveated: the prove-time record for each row is **run 1's** (the clean `sys` profile, also the minimum), with the spread reported: S b4 **1.52 s** (1.52–1.77), S b8 **2.58 s** (2.58–3.18), 2^20 b4 **3.19 s** (3.19–4.22). Footprints and bytes are unaffected by contention and stand on all samples.

## Verdicts against the book (stage-1 rows are informational; the gate is shape P at b4)

| row | pre-registered (book / stage-0 LDE law) | measured (max of samples) | verdict |
|---|---|---|---|
| S b4 footprint | ~5 GB / 5.9 GB | **6.80 GB** | +36 % / +15 % — the LDE law under-projects by ~15 % at this geometry |
| S b4 bytes | ~470 KB | **285,605 B (278.9 KB)** | −39 % — bytes scale with log_height and width, not rows |
| S b8 footprint | — / 11.8 GB | **13.76 GB** | +17 % |
| S b8 bytes | — | **206,221 B (201.4 KB)** | −28 % vs b4 for 2.0× the RAM |
| 2^20 b4 footprint (P-height proxy at S width) | — / 11.8 GB | **14.11 GB** | +20 % |
| **shape P b4, re-projected** = 2^20-b4 measured × 790/702 | 13–14 GB (ruling §3) | **15.6–15.9 GB** vs the 16 GB gate | inside by 1–3 %; **b2 is the lever if stage 2 lands outside** |
| shape P b4 prove, re-projected | ≤ 20 s | ≈ 3.6 s (3.19 s × 790/702) | ample |
