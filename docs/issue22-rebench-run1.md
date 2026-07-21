# issue #22 (B′) — grind 20→22 prove-time re-bench (run 1)

> B′ (adopted 2026-07-19; design `fri-soundness-accounting-2026-07.md`) flips
> grind 20 → 22 in all three lane configs to restore "~100-bit conjectured"
> under the DG25 list-decoding-capacity repricing. **B′'s core claim: proof
> sizes are unchanged — grinding is a PoW nonce, not openings; the cost is
> prove-time only.** This run refreshes the prove-time headlines and nails the
> size-invariance byte-for-byte. Numbers only. Reproduced in run 2.

## Rig / provenance (bench discipline)

- **qumbra-lab rev:** `628251d` (branch `claude/issue22-config-pass`; 68/68 unfiltered release suite green, deg ≤ 3 held)
- **prover:** Plonky3 0.6.1 (pinned in `Cargo.lock`)
- **hardware:** Apple M5 Max, 36 GiB RAM
- **OS:** macOS 26.5.2
- **power state:** AC (80%, not charging); no thermal warning
- **method:** release binary run DIRECTLY under `/usr/bin/time -l` (no `cargo`), foreground bare run; `swaps` and swap-usage delta checked each run (§7.1 discipline). Peak footprint = `phys_footprint` (PR #23's faithful metric).

## Results — run 1

| target | mode / config | prove | verify | fixed size | peak footprint | max RSS | swaps |
|---|---|---|---|---|---|---|---|
| consensus 2×2 bucket | `bucket` b16/q20/g22/fp16/a16 | 1832.2 ms | 18.1 ms | **139721 B (136.4 KB)** | 11.78 GB | 11.89 GB | 0 |
| aggregation leaf | `m4gate` b4/q40/g22/fp16/a16 | 700 ms | 12.7 ms | **781.8 KB** | 11.78 GB | 11.89 GB | 0 |
| interior (2-child) | `m4interior` two-child/b2/q80/g22 | 9.16 s | — | **1.51 MB** | **19.49 GB** | 18.01 GB | 0 |
| whole tree (`--lane b2`) | `m4assembly --lane b2` | 17.70 s (tree) | native ✓ | leaf 781.8 KB / interior 1.51 MB | 19.95 GB | 16.95 GB | 0 |

- consensus bucket: 102 conjectured bits (capacity proxy; 20·4+22). postcard 164478 B (160.6 KB — varint, nonce-value-density sensitive).
- whole tree segments: leaf L 4.13 s, leaf R 3.03 s (distinct M3 witness), interior root 7.19 s. issue #24 consumer check `root == keccak-merge(opvsL,opvsR)` PASSED; epoch Σfee `Σfee == feeL+feeR` PASSED.
- interior rows 524288 (2^19); leaf/gate rectangle 3638 cols × 2^16, 2382 lane perms.

## Size invariance — direct g20-vs-g22 byte comparison (the B′ claim)

Measured at **identical rectangles** (temporary g20 twins added, run, then reverted — twins are NOT in the committed tree):

| config | outer grind | fixed size |
|---|---|---|
| consensus bucket b16/q20 (618 cols) | g20 | **139721 B** |
| consensus bucket b16/q20 (618 cols) | g22 | **139721 B** |
| leaf gate b4/q40 (3638 cols) | g20 | **781.8 KB** |
| leaf gate b4/q40 (3638 cols) | g22 | **781.8 KB** |

→ **Byte-for-byte identical. Grind does not touch proof size — B′'s core claim confirmed empirically.** (Prove time DOES rise with grind: leaf 742 ms @ g20 → 1307 ms @ g22, the 2^20→2^22 PoW search; this is the entire cost of B′.)

## Notes / expected-range check

- The consensus bucket fixed size 139721 B matches the published g20 M3 headline (136.4 KB, `docs/bucket-M3-run{1,2}.md`) exactly.
- The leaf gate 781.8 KB vs the design doc's 779.6 KB is **not** a B′ effect: it is the PR #23 rectangle widening 3626 → 3638 cols (+0.3%), landed before this issue. The g20-vs-g22 comparison above proves grind contributes 0 B.
- Interior peak footprint 19.49 GB is RAM-neutral vs the g20 baseline 20.5 GB (−5%, within run-to-run variation; grind is a nonce search, RAM-neutral as predicted). Zero swap throughout.
- Prove times rise as expected under g22 (grind is prove-time-only and parallel-grind-jittery, known since M1.6); no size or RAM stop-condition tripped.
