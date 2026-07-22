# issue #41 (B″) — q21/q43/q86 re-bench (run 2, reproduction)

> Second independent run on the same rig (bench discipline: a number is
> publishable only after reproduction twice). **Fixed sizes are byte-for-byte
> identical to run 1**; footprints reproduce within variance; zero swap; all
> soundness invariants pass again. See `docs/b2prime-run1.md` for the fit-check
> table, the byte-delta twin comparison, and the soundcalc sanity.

## Rig / provenance

- **qumbra-lab rev:** `75cbf38` (branch `claude/b2prime-q21`; 268/268 unfiltered workspace suite green)
- **prover:** Plonky3 0.6.1 (pinned) · **hardware:** Apple M5 Max, 36 GiB · **OS:** macOS 26.5.2 (25F84) · **power:** AC (80%, not charging), no thermal warning
- **method:** release binary under `/usr/bin/time -l`, foreground bare run; `bincode`-fixed sizes.

## Results — run 2

| target | mode / config | prove | verify | fixed size | peak footprint | max RSS | swaps |
|---|---|---|---|---|---|---|---|
| consensus 2×2 bucket | `bucket` b16/q21/g22/fp16/a16 | 2019.3 ms | 21.7 ms | **145,609 B (142.2 KB)** | 11.08 GB | 11.08 GB | 0 |
| aggregation leaf gate | `m4gate` b4/q43/g22/fp16/a16 | 754 ms | 17.9 ms | **839.2 KB** | — | 15.38 GB | 0 |
| (leaf gate @ b16 blowup) | `m4gate` b16/q21/g22/fp16/a16 | 3001 ms | 7.9 ms | 476.0 KB | 19.96 GB | 15.38 GB | 0 |
| interior (2-child) | `m4interior` two-child/b2/q86/g22 | 7.74 s | — | **1.65 MB** | **20.88 GB** | 16.38 GB | 0 |
| whole tree (`--lane b2`) | `m4assembly --lane b2` | 18.97 s (tree) | native ✓ | leaf 839.2 KB / interior 1.65 MB | **20.90 GB** | 17.72 GB | 0 |

- consensus q20 pre-B″ twin: **139,721 B** (identical to run 1) · postcard varint differs by nonce-value density (q21 171,440 B, q20 164,611 B) as expected; the fixed number is the gate.
- whole-tree segments: leaf L 3.04 s, leaf R 3.14 s, interior root 10.12 s.
- issue #24 consumer check `root == keccak-merge(opvsL,opvsR)` **PASSED**; epoch Σfee `Σfee == feeL+feeR` **PASSED** (Σfee limbs = [973218759,0,0,0]).
- leaf/gate rectangle 3,675 cols × 2^16, 2,485 lane perms (identical).

## Reproduction check vs run 1

| quantity | run 1 | run 2 | reproduces? |
|---|---|---|---|
| consensus fixed size | 145,609 B | 145,609 B | **byte-identical** ✓ |
| consensus q20 twin | 139,721 B | 139,721 B | **byte-identical** ✓ |
| leaf gate fixed | 839.2 KB | 839.2 KB | **identical** ✓ |
| b16/q21 gate fixed | 476.0 KB | 476.0 KB | **identical** ✓ |
| interior fixed | 1.65 MB | 1.65 MB | **identical** ✓ |
| interior rows | 2^19 | 2^19 | ✓ |
| interior footprint | 20.17 GB | 20.88 GB | within variance, both ≤ 32 GB ✓ |
| whole-tree footprint | 20.91 GB | 20.90 GB | ✓ (≤ 32 GB) |
| swaps | 0 | 0 | ✓ |
| issue #24 + Σfee consumer checks | PASS | PASS | ✓ |

Prove times differ run-to-run (consensus 3850→2019 ms, interior 6.86→7.74 s) — the g22 grind heavy-tail, prove-time-only and nonce-driven, documented since M1.6 / issue #22; sizes are unaffected. **All size gates reproduce byte-for-byte; the interior stays inside the 32 GB envelope both runs.**
