# qumbra-lab M1.6 non-geometry levers (blowup 32, FRI arity)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: e909f2c
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, no thermal pressure
- levers: (a) blowup 32 / 18 queries / 10-bit grind = 100 bits conjectured; (b) `max_log_arity` 2..4 (fold arity 4/8/16) at the M1.5 anchor and combined with (a); every config runtime-asserted >= 100 bits
- mock AIR identical to the M1.5 geometry probe (calibrated -0.005% vs the real p3-keccak-air at L1); layouts = narrow rungs L3/L4/L5 plus a new L6 (41 cols x 1536 rows/perm, 50 constraints/row) probing whether higher arity moves the U-curve minimum narrower
- the REAL p3-keccak-air (2633 cols, 3182 constraints/row x 24 rows/perm) runs under every config as a full prove+verify sanity check on a genuine AIR
- workload: 128 permutations-equivalent; per cell prove/verify = best of 3 in-process runs; proof size = postcard bytes

| config | conj. bits | layout | width | prove ms | verify ms | proof KB | vs G0 same layout | vs 150 KB |
|---|---|---|---|---|---|---|---|---|
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | real | 2633 | 129.0 | 3.6 | 477.1 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L3 | 330 | 172.5 | 1.1 | 181.0 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L4 | 164 | 208.6 | 1.0 | 172.5 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L5 | 82 | 283.3 | 1.1 | 177.6 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | L6 | 41 | 426.2 | 1.2 | 189.2 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | N160 | 162 | 627.3 | 1.2 | 207.1 | +0.0 | FAIL |
| G0 (M1.5 anchor) (b16/q23/g10/fp16) | 102 | P371 | 371 | 2034.1 | 1.5 | 256.7 | +0.0 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | real | 2633 | 223.4 | 3.6 | 402.5 | -74.6 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L3 | 330 | 278.2 | 1.0 | 153.9 | -27.0 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L4 | 164 | 358.3 | 0.9 | 146.8 | -25.7 | PASS |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L5 | 82 | 494.2 | 1.0 | 150.6 | -27.0 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | L6 | 41 | 798.8 | 1.4 | 160.4 | -28.9 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | N160 | 162 | 1408.1 | 1.4 | 175.2 | -31.9 | FAIL |
| A: blowup 32 (b32/q18/g10/fp16) | 100 | P371 | 371 | 12949.2 | 1.2 | 216.6 | -40.0 | FAIL |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | real | 2633 | 116.6 | 3.5 | 446.8 | -30.3 | FAIL |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L3 | 330 | 145.3 | 0.8 | 134.2 | -46.8 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L4 | 164 | 175.2 | 0.7 | 116.6 | -55.9 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L5 | 82 | 228.8 | 0.7 | 116.5 | -61.2 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | L6 | 41 | 336.4 | 0.7 | 118.0 | -71.3 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | N160 | 162 | 626.3 | 1.1 | 136.0 | -71.1 | PASS |
| B: arity 4 (b16/q23/g10/fp16/a4) | 102 | P371 | 371 | 2428.2 | 1.6 | 179.6 | -77.1 | FAIL |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | real | 2633 | 139.5 | 4.7 | 439.9 | -37.2 | FAIL |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L3 | 330 | 169.7 | 1.0 | 120.1 | -60.9 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L4 | 164 | 203.4 | 0.8 | 101.5 | -71.0 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L5 | 82 | 274.1 | 0.8 | 99.6 | -78.0 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | L6 | 41 | 388.6 | 0.8 | 99.5 | -89.8 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | N160 | 162 | 665.0 | 1.0 | 117.5 | -89.6 | PASS |
| B: arity 8 (b16/q23/g10/fp16/a8) | 102 | P371 | 371 | 2499.9 | 1.3 | 155.3 | -101.4 | FAIL |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | real | 2633 | 136.9 | 8.3 | 438.5 | -38.6 | FAIL |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L3 | 330 | 164.3 | 4.8 | 116.8 | -64.2 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L4 | 164 | 192.2 | 6.1 | 99.1 | -73.4 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L5 | 82 | 257.2 | 5.8 | 96.4 | -81.3 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | L6 | 41 | 379.4 | 6.6 | 95.4 | -93.8 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | N160 | 162 | 653.4 | 6.9 | 113.3 | -93.7 | PASS |
| B: arity 16 (b16/q23/g10/fp16/a16) | 102 | P371 | 371 | 2479.9 | 6.7 | 150.4 | -106.3 | FAIL |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | real | 2633 | 232.5 | 4.3 | 370.0 | -107.1 | FAIL |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L3 | 330 | 291.1 | 0.8 | 101.2 | -79.7 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L4 | 164 | 370.7 | 0.7 | 85.3 | -87.2 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L5 | 82 | 488.4 | 0.7 | 83.7 | -93.9 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | L6 | 41 | 735.0 | 0.7 | 83.4 | -105.8 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | N160 | 162 | 1404.8 | 0.8 | 98.4 | -108.6 | PASS |
| A+B: blowup 32, arity 8 (b32/q18/g10/fp16/a8) | 100 | P371 | 371 | 15576.1 | 0.7 | 129.6 | -127.1 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | real | 2633 | 201.0 | 5.7 | 368.1 | -109.0 | FAIL |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L3 | 330 | 276.5 | 3.4 | 97.9 | -83.1 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L4 | 164 | 350.8 | 5.1 | 82.9 | -89.6 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L5 | 82 | 449.0 | 5.1 | 80.7 | -97.0 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | L6 | 41 | 719.4 | 5.1 | 79.6 | -109.6 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | N160 | 162 | 1379.9 | 5.1 | 94.6 | -112.4 | PASS |
| A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) | 100 | P371 | 371 | 16267.8 | 3.6 | 125.1 | -131.6 | PASS |

Best cell: L6 @ A+B: blowup 32, arity 16 (b32/q18/g10/fp16/a16) = 79.6 KB — -92.9 KB vs the M1.5 floor (172.5 KB @ L4).
Verdict: <= 150 KB REACHED with non-geometry levers -> M1.5b (correct narrow-Keccak AIR at 41 cols) is justified.
