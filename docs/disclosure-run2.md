# Disclosure-proof measured run 2 (wallet-interop §3) — reproduction

Independent rerun of [run 1](disclosure-run1.md) (fresh process), for the
bench-discipline "reproduced twice on the same rig" bar. Same statement,
circuit, and configs — see run 1 for the full description.

- **hardware**: Apple M5 Max, 36 GiB RAM
- **OS**: macOS 26.5.2
- **qumbra-lab rev**: `1372c45`
- **prover**: Plonky3 0.6.1 (pinned in `Cargo.lock`)
- **power state**: AC, thermal nominal
- **command**: `cargo run --release -p qlab-bench -- disclosure`

## Measured

| config | conj. bits | prove ms | verify ms | postcard KB | fixed KB | vs 2×2 bucket (136.4 KB) |
|---|---|---|---|---|---|---|
| b16/q20/g22 (consensus) | 102 | 593.6 | 26.0 | 141.7 | **121.9** | 0.89× |
| b8/q27/g19 | 100 | 318.7 | 29.7 | 178.0 | 153.3 | 1.12× |
| b4/q40/g20 | 100 | 285.5 | 34.5 | 244.9 | 211.1 | 1.55× |
| b32/q18/g10 | 100 | 965.8 | 26.8 | 133.2 | **114.6** | 0.84× |

## Reproduction verdict

- **Proof size is byte-for-byte identical to run 1** at every config (fixed:
  121.9 / 153.3 / 211.1 / 114.6 KB; postcard within ±0.1 KB rounding on the b32
  cell, 133.2 vs 133.3 KB — a display-rounding artifact of dense-value varint
  counting, same bytes). Size is deterministic — the reported floor is solid.
- **Prove time varies** (e.g. consensus 988 ms → 594 ms) — the grind-PoW
  parallelism jitter documented since M1.6; the ≤3 s target holds with wide
  margin in both runs.
- **Verify time stable** at ~26–35 ms.

Both runs agree on the headline finding: the §3 single-note disclosure proof is
**comparable to (0.84–1.55×), not ≪, the 2×2 bucket**, because a faithful
`addr_commitment` over the 1,184-byte ML-KEM `ek` is a 10-block Keccak sponge.
See [run 1](disclosure-run1.md) §Findings and the design implication.
