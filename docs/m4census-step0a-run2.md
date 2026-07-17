# qumbra-lab M4 step 0a: verifier hash census + wide-lane feasibility

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 02270a1
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC
- design gate: qumbra-design aggregation-rung1.md §4 (~3,000 keccak-f [derived] per inner proof) / §6 (calibration deliverable 1)
- method: counting adapters around every Keccak entry point of the verification config (MMCS leaf sponge, Merkle compress, challenger byte hash); counts read around `verify` only; determinism asserted (two identical censuses) and transcript identity asserted vs the plain config

Phase A — leaf workload: verify one M3 bucket proof (83 perms, 617 cols x 2^18, consensus b16/q20/g20/fp16/a16, 160.7 KB postcard):

| workload | leaf-sponge perms | compress perms | challenger perms | TOTAL keccak-f | challenger detail |
|---|---|---|---|---|---|
| M3 bucket @ consensus | 540 | 1520 | 173 | **2233** | 10 calls / 22448 B |

- design-doc model (aggregation-rung1 §4): ~3,000 keccak-f [derived] -> measured 2233 (-25.6%)

Phase C — interior-node preview: verify one wide-AIR proof (2233 perms) at each lane config:

| lane config | leaf-sponge perms | compress perms | challenger perms | TOTAL keccak-f | challenger detail |
|---|---|---|---|---|---|
| b4/q40/g20/fp16/a16 | 3400 | 2040 | 643 | **6083** | 12 calls / 86300 B |
| b4/q40/g20/a1 | 3800 | 5400 | 679 | **9879** | 25 calls / 89728 B |
| b8/q27/g19/fp16/a16 | 2295 | 1512 | 641 | **4448** | 10 calls / 86236 B |
| b16/q20/g20/fp16/a16 | 1700 | 1220 | 640 | **3560** | 9 calls / 86204 B |

Phase B — wide-lane feasibility: prove 2233 keccak-f on the stock wide AIR (p3-keccak-air, 2,633 cols x 24 rows/perm) at aggregation-lane configs. Peak RSS: rerun a single config under `/usr/bin/time -l` with `--only <cfg>`. Power: AC

| lane config | conj. bits | rows | prove ms | verify ms | postcard KB | fixed KB |
|---|---|---|---|---|---|---|
| b4/q40/g20/fp16/a16 | 100 | 65536 | 455 | 13.4 | 715.4 | 593.4 |
| b4/q40/g20/a1 | 100 | 65536 | 474 | 6.0 | 823.0 | 691.9 |
| b8/q27/g19/fp16/a16 | 100 | 65536 | 842 | 8.8 | 521.2 | 432.1 |
| b16/q20/g20/fp16/a16 | 100 | 65536 | 1544 | 7.0 | 416.4 | 345.0 |

Gate context (aggregation-rung1 §6): leaf <= ~10 s / <= 32 GB, interior <= ~30 s / <= 32 GB on this rig; phase B covers the prove-time half for the *hash workload alone* — constraint-eval glue is step 0b (the verifier circuit itself).

## Peak RSS (measured separately, `/usr/bin/time -l` with `--only <cfg>`, census phases skipped)

| lane config | peak RSS |
|---|---|
| b4/q40/g20/fp16/a16 | 2.87 GB |
| b4/q40/g20/a1 | 2.88 GB |
| b8/q27/g19/fp16/a16 | 5.70 GB |
| b16/q20/g20/fp16/a16 | 11.37 GB |

(RSS runs executed once, after run 2; prove/verify numbers in those runs matched the tables above within jitter.)

## Notes

- Census counts are asserted deterministic (two identical passes) and the counting config's proof is re-verified under the plain config (transcript identity). Proving itself is NOT run-deterministic (parallel grind => different PoW witness => shifted query set, the M1.6 "grind jitter"); census counts are per-proof and reproduced identically across runs 1/2 because verification of a *fixed* proof is deterministic — and the counts also matched across the two independently-generated proofs of runs 1/2.
- Phase B prices the hash workload only; constraint-evaluation/fold-arithmetic glue is step 0b (the actual verifier circuit).
- Width footnote: NARROW_WIDTH prints 617; the M3 write-ups say 618 (comment in narrow.rs also says 618). One-off discrepancy in the docs' favor either way; flagged for whoever touches narrow.rs next.
