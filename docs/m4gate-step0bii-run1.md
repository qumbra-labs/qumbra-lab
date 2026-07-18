# qumbra-lab M4 step 0b(ii): the calibration gate — verifier gate rectangle (run 1)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 5af1d28 (gate-exit worktree, committed on claude/m4-gate-exit)
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, idle rig (record thermal manually)
- rectangle: **3,626 cols x 2^16, 2,382 lane perms**; proves-in-circuit a REAL
  M3 consensus proof (`consensus_proof` + `walk` recorder) with **every gate
  column bound** — FS/draw schedule, query program, ext-arith fold pipeline,
  and **both fold-chain endpoints value-pinned** (M_RO reduced-opening START +
  M_HORN/FPREG END). **Max constraint degree 3** (5,549 constraints:
  {1: 43, 2: 3,135, 3: 2,371}).

| lane config | rows | prove ms | verify ms | postcard KB | fixed KB |
|---|---|---|---|---|---|
| b4/q40/g20/fp16/a16 | 65536 | 667 | 14.1 | 939.3 | 779.6 |
| b16/q20/g20/fp16/a16 | 65536 | 2180 | 7.9 | 546.7 | 453.6 |

## Peak RSS (`/usr/bin/time -l` with `--only`, fresh processes)

| lane config | prove ms (this proc) | peak RSS |
|---|---|---|
| b4/q40/g20/fp16/a16 | 747 | 11.89 GB (11,889,098,752 B) |
| b16/q20/g20/fp16/a16 | 2245 | 16.31 GB (16,307,634,176 B) |

## Calibration verdict vs aggregation-rung1 §6 leaf envelope (≤ 10 s / ≤ 32 GB)

**PASS on both dimensions, with margin, at both configs.**

| config | prove | time margin | peak RSS | RAM margin |
|---|---|---|---|---|
| b4/q40 | 0.67 s | **15×** | 11.89 GB | **2.7×** |
| b16/q20 | 2.18 s | **4.6×** | 16.31 GB | **2.0×** |

The leaf verifier — the actual, fully-constrained, both-endpoints-pinned gate
rectangle proving a real M3 consensus proof — sits comfortably inside the
aggregation leaf envelope. The tree prototype (M4 step 1) is unblocked.

## Column growth (3,532 post-inc-4 → 3,626, +94 cols, +2.7% cells)

All growth is the degree-reduction materialization + endpoint-pin counters
added this branch (no change to the verifier machinery itself):

| block | cols | purpose |
|---|---|---|
| deg-reduction, flush automaton | 11 | CHLIVE/F2SEL/PG_A/PHG/PHDEND/CONT/EG_A/ENDG/XSEL/QADV/CFULL |
| deg-reduction, query selectors | 21 | M3[8]/RLO[4]/RHI[4]/DMUX/SNL[4] |
| deg-reduction, fold pipeline | 38 | GLO[4]/GHI[4]/GF[4]/BPM[4]/FHG[22] |
| endpoint pin, accumulation | 4 | PREGA (preg·fri_alpha) |
| endpoint pin, START captures | 3 | CPA/CPB/CPL (PHD·comparator) |
| endpoint pin, END | 17 | CONSZ7 + FPI[16] |
| **total added** | **94** | materialized products + one-hot counters, all filled by a derived-column pass / write_row |

Materialized products are pure current-row functions filled by `fill_derived`
(mirrors each defining constraint); the FPI counter is filled from the witness
`regs.fpi`. None change the verifier's semantics — they only bring every
constraint within the deg-3 house rule (unblocking a consensus-quotient-degree
bench) and pin the fold-chain endpoints to the transcript.

## Anchors (same rig)

- inc-1 skeleton (synthetic): b4 ≈ 476–561 ms / 3.58 GB / 597.9 KB
- inc-2+3 routing (synthetic): b4 ≈ 455 ms / 3.61 GB / 603.1 KB
- **this (full real gate, all bound): b4 667 ms / 11.89 GB / 779.6 KB**

The step from the inc-3 synthetic skeleton to the full real gate adds the entire
verifier machinery (query program ring, XOR register file, ext-arith fold
pipeline, endpoint pins) — +941 cols and ~2× the constraint count — hence the
prove/RSS/size growth. It is still deep inside the envelope.

## Soundness state at this measurement

Positive accepts the real M3 transcript; **9 tamper negatives bind** —
4 gate-exit (wrong-root / tampered-opening / wrong-challenge / bad-fold) + the
endpoint-pin negatives (pzacc / preg / capture / fpreg / mro) — plus the inc-4
schedule/arith bindings. 32/32 m4gate tests pass. Both fold-chain endpoints are
value-pinned (full end-to-end fold soundness), not merely threading-anchored.
