# M6 devnet — measured run 1 (棒 5)

Real-proof integration measured via `cargo run --release -p qlab-bench -- m6devnet`.

## Environment (bench discipline)

- repo rev: `claude/m6-devnet` @ `7838b86` + 棒 5b (the `m6devnet` mode itself)
- prover: Plonky3 crates pinned `=0.6.1` (Cargo.lock)
- hardware: Apple M5 Max, 36 GiB
- OS: Darwin 25.5.0 (macOS)
- power: AC
- consensus config: `b16/q20/g22` (M3 `CONSENSUS_CFG`), 2^18 rows
- committee: N=20, ⅔-quorum (14); checkpoint cadence 8 blocks
- sim block time: 2 s (accelerated; real target 60–75 s, consensus §7)

## Proof pool (4 real M3 tx proofs, generated once, reused)

| proof | prove time | fixed-width size |
|---|---|---|
| 0 | 3.78 s | 136 KB |
| 1 | 2.88 s | 136 KB |
| 2 | 2.11 s | 136 KB |
| 3 | 2.20 s | 136 KB |

Peak RSS (whole process, `/usr/bin/time -l`): **11.90 GB** — the 4 serial b16
proves; well inside 32 GB.

## Verification / per-block validation

| metric | value |
|---|---|
| single M3 proof verify (best of 3) | **20.091 ms** |
| per-block validation, 4-tx block (`validate_body`) | **74.767 ms** (~18.69 ms/tx) |
| proof bytes / tx | 136 KB (block body ≈ 545 KB for 4 txs) |
| txs/block within the §7 sub-second (1 s) validation budget | **53** |

## Cadence, finality latency, degraded mode

- block cadence: 2 s sim (real 60–75 s)
- checkpoints finalized at heights [8, 16] (⅔ quorum of the N=20 committee)
- finality latency ≈ cadence (8 blocks) = 16 s sim; at real 60–75 s blocks ≈
  **8–10 min** — minutes-class, matching consensus §4
- tip 16 / finalized 16 / status **Final**
- **degraded mode:** committee stalled → PoW chain kept growing 16 → 33 (status
  **Degraded**); a recovery checkpoint → status **Final** (Ebb-and-Flow, §4) ✓

## Finding — verification is NOT sub-ms at the conservative-hash config (design-repo update owed)

Measured single-proof verify is **~20 ms** (Keccak-FRI at `b16/q20/g22`), not the
sub-ms of consensus §5 / performance §5. That sub-ms figure is the **WHIR-class**
target (WHIR 0.4–0.8 ms), and WHIR is not adopted (it remains a watch item). At the
current conservative-hash verifier:

- §7's "sub-ms STARK verification × hundreds of transactions is sub-second per
  block" is **optimistic** — at ~20 ms/proof, roughly **~50 txs/block** (not
  hundreds) fit a 1-second validation budget.
- Verification is nonetheless still cheap and off the critical path: ~50 txs/block
  at 60–75 s blocks is far above the 1–10 TPS envelope, and block validation stays
  well under the block time. The design's "validation is never the bottleneck,
  propagation is" (consensus §1) still holds; only the *absolute* "sub-ms" wording
  is WHIR-gated.

**Owed to the design repo (no silent divergence):** a measured-update to
consensus §5/§7 (and performance §5) noting that "sub-ms verify / hundreds of
txs sub-second" is WHIR-class; the measured conservative-hash verify is ~20 ms →
~50 txs/block for a sub-second budget. (Coordinator lands design-repo edits.)

## Reproduction

See `m6-devnet-run2.md` — verify 20.05 ms, per-block(4) 77.3 ms, RSS 11.90 GB
(prove times vary with parallel-grind PoW jitter, known since M1.6). The
validation-time and RSS numbers reproduce tightly.
