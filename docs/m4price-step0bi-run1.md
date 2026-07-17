# qumbra-lab M4 step 0b(i): verifier arithmetic census + glue pricing

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 9d430f0
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC
- companion to step 0a (`m4census`, hash workload = 2,233 keccak-f); this prices the field-arithmetic glue of aggregation-rung1 §4's +30–50% allowance

## Exact census: M3 bucket constraint DAG (evaluated ONCE, at zeta, in the ext field)

| metric | count |
|---|---|
| constraints | 873 |
| unique DAG ops (add/sub/neg/mul) | 3791 (632/1135/71/1953) |
| leaf reads (unique) | 4419 |
| tree nodes without sharing | 8554 (sharing factor 2.3x) |
| alpha-fold (per constraint) | 873 mul + 873 add |
| quotient chunks | 4 (log 2) |

## Counted-from-shape: per-proof verifier linear algebra (consensus config, all inputs shown)

| term | ext-mul | ext-add/sub | inputs |
|---|---|---|---|
| constraint DAG (once) | 1953 | 1838 | census above |
| alpha fold | 873 | 873 | 873 constraints |
| reduced openings | 25000 | 25000 | 20 q x (1234 main + 16 quotient); + 60 ext-inv |
| FRI binary folds | 560 | 560 | 20 q x 14 folds x ~2 |
| final poly (Horner) | 320 | 320 | 20 q x 16 coeffs |
| zerofier/recombine/misc | 94 | 72 | lde 2^22, 4 chunks |
| **TOTAL** | **28800** | **28663** | + 60 ext-inv |

- glue cells [lean (mul=24, add=4)]: 0.8M vs hash cells 141.1M -> glue = 0.6% of hash (design allowance was +30–50%)
- glue cells [fat  (mul=48, add=8)]: 1.6M vs hash cells 141.1M -> glue = 1.1% of hash (design allowance was +30–50%)

- bucket context: 83 perms, width 617, 2^18 rows; challenger byte-packing / injection routing not priced here (it is hash-adjacent wiring, bounded by opened-value count x small constant — recorded as a 0b(ii) line item).

## Notes

- Census is exact and deterministic (both runs byte-identical modulo the env header): the constraint DAG is walked with Arc-pointer memoization, so shared subexpressions are counted once — matching an evaluator with value reuse. The "counted-from-shape" rows are formulas with every input printed, not estimates.
- Robustness bound: M1.5b measured realized constraint density at 15x the census (prove-time effect). Even if the arithmetic-bank realization suffers the same 15x on the fat bracket, glue = ~24M cells = 17% of the hash workload — still inside the design's +30-50% allowance. The headline (glue is not the cost driver) survives a 15x realization miss.
- Not priced here (0b(ii) line items): challenger byte-packing wiring, opened-value injection routing into banks, and the ext-inv gadget (60 per proof — batched inversion row, negligible).
