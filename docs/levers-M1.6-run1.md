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
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | real | 2633 | 108.3 | 3.4 | 477.2 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L3 | 330 | 121.6 | 1.0 | 181.0 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L4 | 164 | 152.2 | 1.0 | 172.6 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L5 | 82 | 211.7 | 1.0 | 177.5 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L6 | 41 | 316.3 | 1.1 | 189.3 | +0.0 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | real | 2633 | 176.7 | 3.0 | 402.5 | -74.7 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L3 | 330 | 227.9 | 0.8 | 153.9 | -27.0 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L4 | 164 | 278.9 | 0.9 | 146.8 | -25.8 | PASS |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L5 | 82 | 390.8 | 0.9 | 150.6 | -26.9 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L6 | 41 | 622.5 | 0.9 | 160.3 | -29.1 | FAIL |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | real | 2633 | 103.1 | 3.3 | 446.8 | -30.4 | FAIL |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L3 | 330 | 132.4 | 0.8 | 134.4 | -46.6 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L4 | 164 | 141.9 | 0.7 | 116.7 | -55.8 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L5 | 82 | 188.1 | 0.7 | 116.5 | -61.1 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L6 | 41 | 271.9 | 0.6 | 118.0 | -71.3 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | real | 2633 | 106.4 | 3.3 | 440.0 | -37.1 | FAIL |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L3 | 330 | 128.7 | 0.7 | 120.1 | -60.9 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L4 | 164 | 137.5 | 0.6 | 101.6 | -71.0 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L5 | 82 | 183.5 | 0.6 | 99.7 | -77.8 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L6 | 41 | 262.7 | 0.6 | 99.6 | -89.8 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | real | 2633 | 104.9 | 5.5 | 438.4 | -38.8 | FAIL |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L3 | 330 | 114.3 | 3.3 | 116.8 | -64.2 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L4 | 164 | 133.9 | 4.7 | 99.2 | -73.4 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L5 | 82 | 189.8 | 4.5 | 96.5 | -81.0 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L6 | 41 | 267.8 | 4.8 | 95.4 | -93.9 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | real | 2633 | 176.0 | 3.1 | 370.0 | -107.2 | FAIL |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L3 | 330 | 222.9 | 0.6 | 101.1 | -79.9 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L4 | 164 | 242.0 | 0.5 | 85.3 | -87.3 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L5 | 82 | 332.2 | 0.5 | 83.8 | -93.7 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L6 | 41 | 517.4 | 0.5 | 83.5 | -105.8 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | real | 2633 | 183.0 | 5.0 | 368.0 | -109.2 | FAIL |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L3 | 330 | 221.0 | 3.0 | 98.0 | -83.0 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L4 | 164 | 264.1 | 4.1 | 82.9 | -89.7 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L5 | 82 | 395.3 | 4.0 | 80.6 | -96.9 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L6 | 41 | 585.6 | 4.2 | 79.6 | -109.8 | PASS |

Best cell: L6 @ A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) = 79.6 KB — -93.0 KB vs the M1.5 floor (172.6 KB @ L4).
Verdict: <= 150 KB REACHED with non-geometry levers -> M1.5b (correct narrow-Keccak AIR at 41 cols) is justified.
