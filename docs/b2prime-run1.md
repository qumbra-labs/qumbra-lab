# issue #41 (B″) — q21/q43/q86 restore-to-100-bit re-bench (run 1)

> B″ (DECIDED 2026-07-22; design `fri-soundness-accounting-2026-07.md` §6) bumps
> queries in all three lanes — consensus q20→**q21**, leaf q40→**q43**, interior
> q80→**q86** — to restore the ~100-bit conjectured standing invariant under the
> 2025/2197-corrected ceiling (the q20-era configs drop to 96.9 / 96.1 / 94.8;
> the bumps recover 100.6 / 101.6 / 100.2). Unlike B′ (grind, prove-time-only),
> query bumps **pay bytes** and cascade into the leaf/interior gate schedule/shape
> (the #22 lesson). This run confirms the two rectangle fit-checks, the ≤150 KB
> consensus wire, and the 32 GB interior envelope. Numbers only. Reproduced in run 2.

## Rig / provenance (bench discipline)

- **qumbra-lab rev:** `75cbf38` (branch `claude/b2prime-q21`; **268/268 unfiltered `cargo test --release --workspace` green**, deg ≤ 3 held on narrow + interior, all tamper negatives UNSAT)
- **prover:** Plonky3 0.6.1 (pinned in `Cargo.lock`)
- **hardware:** Apple M5 Max, 36 GiB RAM
- **OS:** macOS 26.5.2 (25F84)
- **power state:** AC (80%, not charging); no thermal warning
- **method:** release binary run DIRECTLY under `/usr/bin/time -l` (no `cargo`), foreground bare run; `swaps` checked each run (§7.1). Peak footprint = `peak memory footprint` / `phys_footprint` (PR #23's faithful metric). Sizes are `bincode`-fixed bytes (production-format proxy; grind- and nonce-invariant).

## FIT-CHECKS (the two pre-registered stop-gates) — BOTH PASS

| fit-check | metric | result | verdict |
|---|---|---|---|
| **FC1** leaf 2^16 @ consensus q21 | lane perms → used rows / cap | 2,485 perms → 59,640 rows / 65,536 (**91.0%**) | **rectangle stays 2^16** ✓ (margin ≈ 2.4 queries) |
| **FC2** interior 2^19 @ leaf q43 | used perms → rows / cap | 17,977 perms (childL 8,962 + childR 8,962 + merge 53) → 431,448 rows / 524,288 (**82.3%**) | **rectangle stays 2^19** ✓ (margin ≈ 9 leaf-queries) |

Both are permanent tests (`m4gate::tests::b2prime_fitcheck_{leaf_2p16,interior_2p19}`) that STOP rather than silently promote to 2^17 / 2^20.

## Results — run 1

| target | mode / config | prove | verify | fixed size | peak footprint | max RSS | swaps |
|---|---|---|---|---|---|---|---|
| consensus 2×2 bucket | `bucket` **b16/q21/g22/fp16/a16** | 3850.8 ms | 17.3 ms | **145,609 B (142.2 KB)** | 11.08 GB | 11.08 GB | 0 |
| aggregation leaf gate | `m4gate` **b4/q43/g22/fp16/a16** | 700 ms | 16.9 ms | **839.2 KB** | — | 15.31 GB | 0 |
| (leaf gate @ b16 blowup) | `m4gate` b16/q21/g22/fp16/a16 | 2145 ms | 7.6 ms | 476.0 KB | — | 15.31 GB | 0 |
| interior (2-child) | `m4interior` **two-child/b2/q86/g22** | 6.86 s | — | **1.65 MB** | **20.17 GB** | 16.36 GB | 0 |
| whole tree (`--lane b2`) | `m4assembly --lane b2` | 20.63 s (tree) | native ✓ | leaf 839.2 KB / interior 1.65 MB | **20.91 GB** | 17.32 GB | 0 |

- consensus bucket q21: 106 capacity-proxy bits (21·4+22); **2197-corrected conjectured ceiling 100.6**. postcard 171,440 B (160.8 KB — varint, nonce-value-density sensitive; the fixed number is the gate).
- leaf/gate rectangle **3,675 cols × 2^16, 2,485 lane perms** (was 3,672 / 2,382 at q20 — GATE_WIDTH +3 from consensus q21's GRP/IDXR/QSEL; +103 perms from the 21st query).
- interior rows **524,288 (2^19)**; whole-tree segments: leaf L 4.38 s, leaf R 4.47 s (distinct M3 witness), interior root 7.31 s.
- issue #24 consumer check `root == keccak-merge(opvsL,opvsR)` **PASSED**; epoch Σfee `Σfee == feeL+feeR` **PASSED** (Σfee limbs = [973218759,0,0,0]).

## Byte delta — the cost of B″ (consensus q20→q21, same-rectangle twin)

| config | outer queries | fixed size |
|---|---|---|
| consensus bucket b16/q20/g22 (pre-B″ ref) | q20 | **139,721 B** (136.4 KB) |
| consensus bucket b16/q21/g22 (B″) | q21 | **145,609 B** (142.2 KB) |

→ **+5,888 B (+5.75 KB) per the +1 query.** The pre-B″ q20 number reproduces the published M3 headline (139,721 B) byte-for-byte. Consensus wire **142.2 KB ≤ 150 KB** — margin now 7.8 KB (was 13.6 KB), i.e. "half the remaining margin" exactly as §6 predicted. Every published headline size is now the q21 number.

## soundcalc-style sanity (issue #41 item 5) — no non-query term drops below the new query floors

The query bump raises ONLY the query term; every non-query term (batching / commit / ALI / DEEP) is query-count-independent (trace-size / width / field driven) and is UNCHANGED from `docs/issue22-soundcalc.md`. Proven-Johnson (JBR) query terms, recomputed with the B″ counts (bits/query from §3: b16 1.96, b4 0.96, b2 0.44; +22 grind):

| lane | JBR query (q20-era → B″) | nearest non-query term (unchanged) | binding min |
|---|---|---|---|
| consensus b16/q21 | 61 → **63** | batching **60** | 60 (batching — unchanged, the known JBR min) |
| leaf b4/q43 | 60 → **63** | batching 69 | 63 (query — rose from 60) |
| interior b2/q86 | 57 → **60** | batching 71 | 60 (query — rose from 57) |

No non-query term newly drops below a query floor: the query bump only RAISES query terms, so the proven floor is unchanged (consensus, still batching-bound 60) or rises (leaf 60→63, interior 57→60). The commit-phase field cap (~80-82) is query-independent and untouched. **Stop-condition (a non-query term dragging a total below its expected floor) NOT tripped.** The conjectured (2197-corrected) ceilings 100.6/101.6/100.2 are the B″ deliverable and are the query-term-plus-grind figures; soundcalc does not model the conjectured regime (removed post-DG25), so it neither moves nor contradicts them.

## Notes / expected-range check

- Consensus prove time is grind-dominated (2^22 PoW) with the **heavy tail** documented since M1.6 / issue #22: this run 3850.8 ms, but the SIZE (145,609 B) is deterministic (grind is a nonce). See run 2 (2019.3 ms) — the ≤3 s laptop target is met in the expected case; the tail is a known g22 property, unchanged by the query bump.
- Interior b2/q86 footprint 20.17 GB is +~0.7 GB over the pre-B″ q80 (~19.5 GB), consistent with the +7.5% verification workload; **inside the 32 GB envelope with ~11 GB (37%) margin**. Zero swap throughout every run.
- Leaf gate 839.2 KB vs pre-B″ 781.8 KB (+57 KB): the leaf now commits 43 queries (was 40) of a 3,675-col rectangle (was 3,672) — the aggregation lane pays bytes for its own q43, well inside the ≤10 s / ≤32 GB leaf envelope.
