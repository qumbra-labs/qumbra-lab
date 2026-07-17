# qumbra-lab M4 step 0b(ii) anchor: ext-mul bank, measured

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: fa358c5
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC
- bank: 12 cols x 2^15 rows = one deg-4 ext-mul/row (c = a*b over KoalaBear[x]/(x^4 - 3), 4 constraints, degree 2); trace values cross-checked against p3's own ext arithmetic
- pins step 0b(i)'s bracketed price: 12 cells/mul by construction; the anchor validates prover throughput, quotient shape, and proof-byte impact on a tall-skinny rectangle

| lane config | prove ms | verify ms | postcard KB | fixed KB |
|---|---|---|---|---|
| b4/q40/g20/fp16/a16 | 63.1 | 6.3 | 104.0 | 90.9 |
| b8/q27/g19/fp16/a16 | 46.7 | 2.9 | 75.9 | 66.3 |
| b16/q20/g20/fp16/a16 | 68.4 | 2.4 | 60.6 | 52.8 |

Composite projection [projected — the full build is 0b(ii)]: one rectangle 2673 cols x 2^16 rows = 175M cells = +1.5% over the measured hash-only rectangle (173M, the b4 456 ms / 2.87 GB baseline); row budget: keccak 53592, mul bank 28800, add bank 7166 — all inside 2^16 with slack. Projected b4 leaf: ~463 ms prove / ~2.91 GB RSS.

## Notes

- The bank is real arithmetic, not a mock: trace values are computed with p3's own BinomialExtensionField multiply and the 4 degree-2 constraints re-derive them limb-wise (W=3); a wrong c fails verification.
- Prove-time jitter across runs (36-107 ms band) is thermal/scheduler noise on a sub-100ms workload; proof bytes are stable to the byte. The anchor's purpose is the price validation, not a timing record.
- Projection accounting: comparison is rectangle-to-rectangle (the 0a baseline was already 2^16-padded), so the marginal cost of banks+routing is the added 40 columns = +1.5%. Utilized-cell accounting (0b(i)'s 0.6-1.1%) and the pow2 height padding are separate lines that cancel across baselines.
