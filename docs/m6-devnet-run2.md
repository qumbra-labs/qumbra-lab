# M6 devnet — measured run 2 (棒 5, reproduction)

Independent rerun of `cargo run --release -p qlab-bench -- m6devnet` — the
second reproduction required by the bench discipline. Same environment as
`m6-devnet-run1.md` (repo `7838b86` + 棒 5b, Apple M5 Max / 36 GiB, Darwin
25.5.0, AC, config `b16/q20/g22`).

## Proof pool (4 real M3 tx proofs)

| proof | prove time | fixed-width size |
|---|---|---|
| 0 | 3.29 s | 136 KB |
| 1 | 1.97 s | 136 KB |
| 2 | 1.99 s | 136 KB |
| 3 | 2.01 s | 136 KB |

Peak RSS: **11.90 GB**.

## Verification / per-block validation

| metric | run 2 | run 1 | reproduces? |
|---|---|---|---|
| single M3 proof verify (best of 3) | **20.046 ms** | 20.091 ms | ✓ tight |
| per-block validation, 4-tx block | **77.313 ms** (~19.33 ms/tx) | 74.767 ms | ✓ |
| txs/block within the 1 s budget | **51** | 53 | ✓ |
| proof bytes / tx | 136 KB | 136 KB | ✓ |
| peak RSS | 11.90 GB | 11.90 GB | ✓ |

Prove times differ run-to-run (2.0–3.3 s) — the parallel-grind PoW witness
jitter known since M1.6; not run-deterministic and not a reported gate metric.
The **validation-time** and **RSS** numbers — the metrics that matter here —
reproduce tightly.

## Cadence, finality latency, degraded mode

Identical to run 1: checkpoints at [8, 16]; finality latency ≈ 8 blocks
(minutes-class at real block time); tip 16 / finalized 16 / **Final**;
degraded-mode stall 16 → 33 (**Degraded**) → recovery finalize → **Final**.

## Verdict

Both runs agree: **per-block validation ≈ 75–77 ms for 4 real M3 proofs
(~19–20 ms/proof)**, ~51–53 txs/block within a 1 s budget, RSS ~11.9 GB, clean
finality + degraded-mode transitions. The ~20 ms/proof verify (not sub-ms) is the
reproduced conservative-hash reality; the §5/§7 sub-ms wording is WHIR-class — a
design-repo measured-update is owed (detailed in `m6-devnet-run1.md`).
