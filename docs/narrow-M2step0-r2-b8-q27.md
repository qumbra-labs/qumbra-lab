# qumbra-lab M1.5b real narrow-Keccak AIR bench

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 381352d
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, no thermal pressure
- AIR: qlab-air NarrowKeccakAir — correct Keccak-f[1600] semantics, 402 cols x 3072 rows/perm (128 rows/round), 27 periodic columns (free), 1 preprocessed column (iota RC; vk-style commit excluded from prove time, per-query openings included in proof size)
- semantics validated in qlab-air tests: chain of materialized states == reference keccak-f (itself cross-checked against p3-keccak)
- workload: 96-perm bucket = 294912 rows, padded to 2^19 (the pipeline chains through padding; every padded block is also a genuine keccak round)
- per cell: prove/verify = best of 3 in-process runs; proof = postcard bytes

| config | conj. bits | prove ms | verify ms | proof KB | vs P371 mock | vs gates |
|---|---|---|---|---|---|---|
| b8/q27/g19/a16 (b8/q27/g19/fp16/a16) | 100 | 1151.7 | 17.0 | 172.7 | measure P371 in `levers` | FAIL |

Gates (layout doc §4): size within 10% of the P371 mock at the same config; prove <= 3,000 ms; correctness = qlab-air test suite.
