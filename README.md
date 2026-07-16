# qumbra-lab

Prototype lab for **Qumbra** — the post-quantum privacy-chain design exercise documented in [`lai3d/bidot-blockchains-design/qumbra/`](https://github.com/lai3d/bidot-blockchains-design/tree/main/qumbra).

This repo is where the design thread's **prototype-gated open questions** get answered with code. It is not a chain implementation; it is the lab that decides whether one is worth building. Private, personal, no audience but Larry.

## Relationship to the design docs

The eight design docs closed every doc-shaped question and left exactly these prototype-gated residuals:

| Open question | Owner doc | What this repo must produce |
|---|---|---|
| Hash choice: Keccak vs SHA-256 vs BLAKE3 raw-AIR in-circuit | [performance-budget](https://github.com/lai3d/bidot-blockchains-design/blob/main/qumbra/performance-budget.md) §2 | prover-side bench of the conservative-hash candidates (BLAKE3 raw-AIR numbers are unpublished anywhere — we have to measure) |
| Proof size at our circuit shape | performance-budget §3 | measured FRI proof sizes for the ~90-hash 2×2-bucket circuit vs the ≤150 KB tx target |
| Proving time: ≤3 s laptop / ≤15 s phone | performance-budget §4 | wall-clock on real hardware; the 15 s phone target is *the riskiest number in the whole design* — go/no-go lives here |
| Emission/penalty/slashing constants | tokenomics §7, committee-and-governance §7 | a consensus-parameters appendix, gated on the benchmarks above |

## Milestone 1 — the circuit prototype + hash bench

Scope (deliberately minimal):

1. **Circuit prototype** (Plonky3-class raw AIR, fixed shape, no zkVM): 2 × depth-32 Merkle membership + 2 × nullifier PRF + 2 × commitment well-formedness + in-circuit balance — the transaction-model doc's 2×2 bucket, ~90 hash invocations.
2. **Hash matrix**: the same circuit instantiated over Poseidon2 (baseline; known numbers to validate our rig against) and the conservative candidates (Keccak-f, SHA-256, BLAKE3 raw-AIR).
3. **Measurements per cell**: trace dimensions, proving wall-clock (M-series + x86), peak memory, proof size at ~100-bit conjectured security.
4. **Report**: results written back into the design repo as `qumbra/prototype-bench-M1.md` (EN+ZH), updating performance-budget §2/§3's `[BENCH]`-derived estimates with measured reality.

Explicitly out of scope for M1: phone builds (M2 — needs the M1 rig first), recursion/aggregation (rung 1), note encryption, networking, consensus. One milestone, one question: *what does the conservative-hash decision actually cost, measured?*

## Layout

```
crates/
  qlab-air/     # the fixed-shape AIR: Merkle path, PRF, commitment, balance
  qlab-bench/   # bench harness: hash matrix × hardware, criterion-based
docs/           # lab notes; polished results go to the design repo, not here
```

## Ground rules

- Rust, Plonky3-class stack; pin exact revs in `Cargo.lock` (bench numbers are meaningless against a moving prover).
- Every bench result records: git rev of this repo, prover crate revs, hardware, OS, power state.
- Numbers land in the design repo only after being reproduced twice on the same rig.
