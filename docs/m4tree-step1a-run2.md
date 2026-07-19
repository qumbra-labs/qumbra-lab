# qumbra-lab M4 step 1a: interior-node recorder + census (run 2)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: gate-exit base 7a7921b + `claude/m4-tree-step1`
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, idle rig
- input: identical to run 1 (b4/q40/g20/fp16/a16 leaf wide proof).

## Interior-node workload — verifying ONE child leaf wide proof

| metric | value |
|---|---|
| keccak-f total | **7,503** (leaf-sponge 4,560 + compress 2,040 + challenger 903) |
| opened values / query | 7,260 (trace-local 3,626 + trace-next 3,626 + quotient 8) |
| reduced-opening values | 290,400 = 40 q × 7,260 |
| FRI rounds | 3 (log-arities [4, 4, 4]) |
| native perms recorded | 8,138 |

## Reproducibility

The census counts are **structural** (derived from the recorded `Schedule`'s
shape, not from timing), so run 2 is **bit-identical** to run 1 across every
metric above — the recorder is deterministic. (The underlying leaf proof carries
the usual parallel-grind PoW jitter in its bytes, but that does not change any
recorded count.) Recorder acceptance (native `verify()`) passed on both runs.

## Verdict

Reproduced twice, same rig. Interior hash workload = **7,503 keccak-f/child**
(census projection 6,083 corrected upward +23 %); interior reduced-opening
arithmetic = **290,400 values/child ≈ 11.6× the leaf**. Both feed stage 2 (the
interior circuit) and stage 3 (the ≤ 30 s / ≤ 32 GB interior calibration, the
flagged core risk). Recorder + census foundation complete.
