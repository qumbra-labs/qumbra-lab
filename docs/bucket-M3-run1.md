# qumbra-lab M3 full 2x2 bucket bench

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: 00c7fc1
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, no thermal pressure
- statement: 2 inputs (nk/rkm derivation, nullifier, commitment opening, depth-32 membership in one shared tree) + 2 outputs + in-circuit balance + public binding of anchor/nf/cm'/fee (83 perms incl. warm-up, 617 cols x 2^18 rows)
- semantics: qlab-air test suite (reference-checked chains, equality banks, negative tests for tampered witness and wrong public values)
- per cell: prove/verify = best of 3 in-process runs; proof = postcard bytes

- proof KB reported twice: postcard (varint — the campaign codec, which under-counts dense values on dummy traces and over-counts them ~20% vs a fixed-width wire format) and bincode-fixed (4 B per field element, the production-format proxy; gate verdicts use it)

| config | conj. bits | prove ms | verify ms | postcard KB | fixed KB | vs gates |
|---|---|---|---|---|---|---|
| b16/q20/g20/fp32/a16 (b16/q20/g20/fp32/a16) | 100 | 1574.7 | 20.3 | 160.9 | 136.7 | PASS |
| b4/q45/g10/a16 (b4/q45/g10/fp16/a16) | 100 | 659.3 | 28.2 | 309.2 | 263.3 | FAIL |
| b4/q40/g20/a16 (b4/q40/g20/fp16/a16) | 100 | 611.1 | 27.2 | 277.8 | 236.4 | FAIL |
| b8/q30/g10/a16 (b8/q30/g10/fp16/a16) | 100 | 956.1 | 23.9 | 221.4 | 188.3 | FAIL |
| b8/q27/g19/a16 (b8/q27/g19/fp16/a16) | 100 | 974.7 | 23.3 | 201.9 | 171.6 | FAIL |
| b16/q20/g20/a16 (b16/q20/g20/fp16/a16) | 100 | 1655.5 | 20.1 | 160.7 | 136.4 | PASS |
| b16/q19/g24/a16 (b16/q19/g24/fp16/a16) | 100 | 2000.8 | 20.6 | 153.9 | 130.7 | PASS |
| b16/a16 (b16/q23/g10/fp16/a16) | 102 | 1686.0 | 22.9 | 180.9 | 153.7 | FAIL |
| b32/a16 (b32/q18/g10/fp16/a16) | 100 | 3106.2 | 23.1 | 151.1 | 128.3 | FAIL |

Gates: <= 150 KB and <= 3,000 ms at the consensus config b16/q20/g20/fp16/a16.
