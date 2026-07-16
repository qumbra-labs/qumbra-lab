# qumbra-lab M1.6 non-geometry levers (blowup 32, FRI arity)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 1249dfd
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, 80% battery, no thermal pressure
- levers: (a) blowup 32 / 18 queries / 10-bit grind = 100 bits conjectured; (b) `max_log_arity` 2..4 (fold arity 4/8/16) at the M1.5 anchor and combined with (a); every config runtime-asserted >= 100 bits
- mock AIR identical to the M1.5 geometry probe (calibrated -0.005% vs the real p3-keccak-air at L1); layouts = narrow rungs L3/L4/L5 plus a new L6 (41 cols x 1536 rows/perm, 50 constraints/row) probing whether higher arity moves the U-curve minimum narrower
- the REAL p3-keccak-air (2633 cols, 3182 constraints/row x 24 rows/perm) runs under every config as a full prove+verify sanity check on a genuine AIR
- workload: 128 permutations-equivalent; per cell prove/verify = best of 3 in-process runs; proof size = postcard bytes

| config | conj. bits | layout | width | prove ms | verify ms | proof KB | vs G0 same layout | vs 150 KB |
|---|---|---|---|---|---|---|---|---|
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | real | 2633 | 121.6 | 3.4 | 477.0 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L3 | 330 | 127.3 | 1.0 | 180.9 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L4 | 164 | 153.6 | 1.0 | 172.5 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L5 | 82 | 218.3 | 1.0 | 177.5 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L6 | 41 | 316.6 | 1.1 | 189.3 | +0.0 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | real | 2633 | 178.0 | 3.1 | 402.5 | -74.6 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L3 | 330 | 236.3 | 0.9 | 154.1 | -26.8 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L4 | 164 | 282.7 | 0.9 | 146.8 | -25.7 | PASS |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L5 | 82 | 396.7 | 0.9 | 150.6 | -26.9 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L6 | 41 | 621.1 | 1.0 | 160.4 | -29.0 | FAIL |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | real | 2633 | 104.9 | 3.5 | 446.7 | -30.3 | FAIL |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L3 | 330 | 119.0 | 0.8 | 134.2 | -46.7 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L4 | 164 | 152.7 | 0.7 | 116.7 | -55.8 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L5 | 82 | 204.5 | 0.7 | 116.5 | -61.1 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L6 | 41 | 285.6 | 0.7 | 118.0 | -71.3 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | real | 2633 | 101.6 | 3.7 | 439.9 | -37.1 | FAIL |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L3 | 330 | 118.7 | 0.7 | 120.0 | -60.9 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L4 | 164 | 137.3 | 0.6 | 101.5 | -71.0 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L5 | 82 | 184.1 | 0.6 | 99.6 | -77.9 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L6 | 41 | 276.2 | 0.6 | 99.6 | -89.7 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | real | 2633 | 101.9 | 5.8 | 438.5 | -38.5 | FAIL |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L3 | 330 | 117.3 | 3.7 | 116.8 | -64.1 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L4 | 164 | 139.7 | 3.7 | 99.2 | -73.3 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L5 | 82 | 181.7 | 5.1 | 96.4 | -81.1 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L6 | 41 | 296.1 | 5.4 | 95.6 | -93.7 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | real | 2633 | 181.8 | 3.3 | 369.9 | -107.1 | FAIL |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L3 | 330 | 213.6 | 0.6 | 101.1 | -79.8 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L4 | 164 | 253.1 | 0.5 | 85.3 | -87.2 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L5 | 82 | 348.3 | 0.5 | 83.8 | -93.7 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L6 | 41 | 528.8 | 0.5 | 83.4 | -105.9 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | real | 2633 | 179.8 | 5.3 | 368.1 | -108.9 | FAIL |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L3 | 330 | 211.8 | 3.0 | 97.9 | -83.0 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L4 | 164 | 263.8 | 3.7 | 82.8 | -89.7 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L5 | 82 | 371.9 | 4.0 | 80.6 | -96.9 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L6 | 41 | 511.1 | 3.8 | 79.6 | -109.7 | PASS |

Best cell: L6 @ A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) = 79.6 KB — -92.9 KB vs the M1.5 floor (172.5 KB @ L4).
Verdict: <= 150 KB REACHED with non-geometry levers -> M1.5b (correct narrow-Keccak AIR at 41 cols) is justified.
