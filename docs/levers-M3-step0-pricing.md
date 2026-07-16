# qumbra-lab M1.6 non-geometry levers (blowup 32, FRI arity)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 738490b
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, no thermal pressure
- levers: (a) blowup 32 / 18 queries / 10-bit grind = 100 bits conjectured; (b) `max_log_arity` 2..4 (fold arity 4/8/16) at the M1.5 anchor and combined with (a); every config runtime-asserted >= 100 bits
- mock AIR identical to the M1.5 geometry probe (calibrated -0.005% vs the real p3-keccak-air at L1); layouts = narrow rungs L3/L4/L5 plus a new L6 (41 cols x 1536 rows/perm, 50 constraints/row) probing whether higher arity moves the U-curve minimum narrower
- the REAL p3-keccak-air (2633 cols, 3182 constraints/row x 24 rows/perm) runs under every config as a full prove+verify sanity check on a genuine AIR
- workload: 128 permutations-equivalent; per cell prove/verify = best of 3 in-process runs; proof size = postcard bytes

| config | conj. bits | layout | width | prove ms | verify ms | proof KB | vs G0 same layout | vs 150 KB |
|---|---|---|---|---|---|---|---|---|
| C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) | 100 | real | 2633 | 139.7 | 5.1 | 394.6 | n/a | FAIL |
| C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) | 100 | L3 | 330 | 131.5 | 3.2 | 103.4 | n/a | PASS |
| C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) | 100 | L4 | 164 | 135.9 | 4.0 | 87.3 | n/a | PASS |
| C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) | 100 | L5 | 82 | 207.1 | 4.1 | 84.5 | n/a | PASS |
| C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) | 100 | L6 | 41 | 276.2 | 4.9 | 83.5 | n/a | PASS |
| C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) | 100 | N160 | 162 | 476.5 | 3.9 | 99.7 | n/a | PASS |
| C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) | 100 | P-real | 554 | 2458.6 | 4.6 | 157.1 | n/a | FAIL |
| C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) | 100 | M3-est | 560 | 2508.5 | 5.4 | 158.0 | n/a | FAIL |

Best cell: L6 @ C: consensus b16/q20/g20 (b16/q20/g20/fp16/a16) = 83.5 KB.
Verdict: <= 150 KB REACHED with non-geometry levers -> M1.5b (correct narrow-Keccak AIR at 41 cols) is justified.
