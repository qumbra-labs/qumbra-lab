# qumbra-lab M1.6 non-geometry levers (blowup 32, FRI arity)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 2165d98
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, no thermal pressure
- levers: (a) blowup 32 / 18 queries / 10-bit grind = 100 bits conjectured; (b) `max_log_arity` 2..4 (fold arity 4/8/16) at the M1.5 anchor and combined with (a); every config runtime-asserted >= 100 bits
- mock AIR identical to the M1.5 geometry probe (calibrated -0.005% vs the real p3-keccak-air at L1); layouts = narrow rungs L3/L4/L5 plus a new L6 (41 cols x 1536 rows/perm, 50 constraints/row) probing whether higher arity moves the U-curve minimum narrower
- the REAL p3-keccak-air (2633 cols, 3182 constraints/row x 24 rows/perm) runs under every config as a full prove+verify sanity check on a genuine AIR
- workload: 128 permutations-equivalent; per cell prove/verify = best of 3 in-process runs; proof size = postcard bytes

| config | conj. bits | layout | width | prove ms | verify ms | proof KB | vs G0 same layout | vs 150 KB |
|---|---|---|---|---|---|---|---|---|
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | real | 2633 | 103.7 | 3.4 | 477.1 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L3 | 330 | 129.5 | 1.0 | 180.9 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L4 | 164 | 154.3 | 1.0 | 172.4 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L5 | 82 | 212.4 | 1.0 | 177.5 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L6 | 41 | 328.2 | 1.1 | 189.2 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | N160 | 162 | 487.7 | 1.1 | 207.0 | +0.0 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | real | 2633 | 187.4 | 3.1 | 402.6 | -74.5 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L3 | 330 | 226.9 | 0.8 | 153.9 | -27.0 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L4 | 164 | 317.8 | 0.9 | 146.8 | -25.7 | PASS |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L5 | 82 | 415.1 | 0.9 | 150.6 | -26.9 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L6 | 41 | 605.1 | 0.9 | 160.4 | -28.9 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | N160 | 162 | 1156.9 | 1.0 | 175.2 | -31.8 | FAIL |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | real | 2633 | 107.8 | 3.3 | 446.8 | -30.4 | FAIL |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L3 | 330 | 118.6 | 0.8 | 134.3 | -46.6 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L4 | 164 | 143.2 | 0.7 | 116.7 | -55.8 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L5 | 82 | 195.5 | 0.7 | 116.5 | -61.1 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L6 | 41 | 293.4 | 0.7 | 118.0 | -71.2 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | N160 | 162 | 469.0 | 0.8 | 136.0 | -71.0 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | real | 2633 | 103.5 | 3.5 | 440.0 | -37.1 | FAIL |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L3 | 330 | 115.8 | 0.7 | 120.1 | -60.9 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L4 | 164 | 138.8 | 0.6 | 101.6 | -70.9 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L5 | 82 | 182.5 | 0.6 | 99.6 | -77.9 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L6 | 41 | 278.8 | 0.6 | 99.5 | -89.7 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | N160 | 162 | 453.5 | 0.7 | 117.5 | -89.5 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | real | 2633 | 109.4 | 6.0 | 438.4 | -38.7 | FAIL |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L3 | 330 | 118.8 | 3.4 | 116.8 | -64.1 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L4 | 164 | 137.2 | 4.5 | 99.2 | -73.2 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L5 | 82 | 192.2 | 5.6 | 96.4 | -81.1 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L6 | 41 | 273.0 | 5.5 | 95.4 | -93.8 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | N160 | 162 | 455.9 | 5.3 | 113.3 | -93.7 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | real | 2633 | 183.1 | 3.3 | 369.9 | -107.2 | FAIL |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L3 | 330 | 221.1 | 0.6 | 101.2 | -79.7 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L4 | 164 | 257.1 | 0.5 | 85.3 | -87.1 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L5 | 82 | 343.6 | 0.5 | 83.8 | -93.7 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L6 | 41 | 528.5 | 0.5 | 83.5 | -105.8 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | N160 | 162 | 1051.7 | 0.6 | 98.4 | -108.6 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | real | 2633 | 177.6 | 5.2 | 368.1 | -109.0 | FAIL |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L3 | 330 | 217.0 | 3.0 | 97.9 | -83.0 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L4 | 164 | 257.3 | 3.8 | 82.9 | -89.5 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L5 | 82 | 341.5 | 3.9 | 80.7 | -96.8 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L6 | 41 | 505.4 | 4.9 | 79.6 | -109.6 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | N160 | 162 | 1053.2 | 3.8 | 94.6 | -112.4 | PASS |

Best cell: L6 @ A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) = 79.6 KB — -92.8 KB vs the M1.5 floor (172.4 KB @ L4).
Verdict: <= 150 KB REACHED with non-geometry levers -> M1.5b (correct narrow-Keccak AIR at 41 cols) is justified.
