# qumbra-lab M4 step 0b(ii) increments 2+3: injection routing + FS byte-packing (run 2, fresh process)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 89996dc (m4route worktree, committed on claude/m4-0bii-inc23)
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, 80% batt, idle rig
- same binary, spec, and schedule as run 1 (2,685 cols x 2^16; 18,360
  routed values; 1,376 draws = 1,364 emitted + 12 rejected — the schedule
  is seed-deterministic, so the shape reproduces exactly)

| lane config | rows | prove ms | verify ms | postcard KB | fixed KB |
|---|---|---|---|---|---|
| b4/q40/g20/fp16/a16 | 65536 | 497 | 11.4 | 727.0 | 603.1 |
| b16/q20/g20/fp16/a16 | 65536 | 1457 | 6.6 | 423.2 | 350.6 |

## Peak RSS (`/usr/bin/time -l` with `--only`, fresh processes)

| lane config | peak RSS |
|---|---|
| b4/q40/g20/fp16/a16 | 3.61 GB (3,610,968,064 B) |
| b16/q20/g20/fp16/a16 | 12.28 GB (12,278,218,752 B) |

## Reproduction verdict

- prove: b4 455 → 497 ms, b16 1,503 → 1,457 ms across the two runs —
  normal prove jitter (parallel-grind PoW + thermal, known since M1.6),
  both inside increment 1's band.
- bytes: fixed-width identical to the byte (603.1 / 350.6 KB); postcard
  ±0.2 KB (grind-dependent varint density, the known codec artifact).
- peak RSS: identical to within 3 MB on b4 and 49 KB on b16.

Both runs reproduce; the numbers are publishable per the bench
discipline (two fresh-process runs on the same rig).
