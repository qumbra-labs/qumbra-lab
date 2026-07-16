# qumbra-lab M1.5b real narrow-Keccak AIR bench

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: e909f2c
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, no thermal pressure
- AIR: qlab-air NarrowKeccakAir — correct Keccak-f[1600] semantics, 371 cols x 3072 rows/perm (128 rows/round), 27 periodic columns (free), 1 preprocessed column (iota RC; vk-style commit excluded from prove time, per-query openings included in proof size)
- semantics validated in qlab-air tests: chain of materialized states == reference keccak-f (itself cross-checked against p3-keccak)
- workload: 96-perm bucket = 294912 rows, padded to 2^19 (the pipeline chains through padding; every padded block is also a genuine keccak round)
- per cell: prove/verify = best of 3 in-process runs; proof = postcard bytes

| config | conj. bits | prove ms | verify ms | proof KB | vs P371 mock | vs gates |
|---|---|---|---|---|---|---|
| b16/q20/g20/a16 (b16/q20/g20/fp16/a16) | 100 | 1905.1 | 11.9 | 147.7 | measure P371 in `levers` | PASS |
| b16/q19/g24/a16 (b16/q19/g24/fp16/a16) | 100 | 1964.2 | 11.9 | 141.2 | measure P371 in `levers` | PASS |
| b16/a16 (b16/q23/g10/fp16/a16) | 102 | 1844.9 | 12.9 | 167.5 | measure P371 in `levers` | FAIL |
| b32/a16 (b32/q18/g10/fp16/a16) | 100 | 14173.9 | 11.7 | 139.3 | measure P371 in `levers` | FAIL |

Gates (layout doc §4): size within 10% of the P371 mock at the same config; prove <= 3,000 ms; correctness = qlab-air test suite.
