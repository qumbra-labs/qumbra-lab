# M9-N3 — real RandomX PoW + LWMA-120 difficulty (issue #50)

Builder-session status. Branch `claude/m9-n3`; PR open, **not merged** (coordinator
acceptance). Conflict boundary honored: only `qlab-devnet`'s PoW-related modules +
the new `qlab-pow` crate were touched; **zero contact with `qlab-bench` / `m4gate`**.

## What landed

The M6 devnet's Keccak PoW **placeholder** is replaced by the real
CPU-friendly algorithm the design docs called for (consensus-and-network §10,
protocol-spec §6): **RandomX**, with an **LWMA-120** difficulty retarget and
Monero-shape **key-block rotation**.

### New crate `qlab-pow` (dependency-light primitives; no workspace deps)

- `randomx` — deterministic light-mode RandomX over `randomx-rs 1.4.1` (reference
  tevador/RandomX), memoizing the ~256 MiB cache/VM by key. Cross-checked against
  the **four official `tests.cpp` reference vectors**; flag-independence
  (recommended vs `FLAG_DEFAULT`), determinism, and key/input sensitivity proven.
- `keyblock` — `key_seed_height(height, epoch, lag)` + `KeyBlockSchedule`. Monero
  shape (epoch of `epoch` blocks, seed buried by `lag`); division form so
  non-power-of-two epochs work, proven bit-identical to Monero's
  `(h-lag-1) & ~(epoch-1)` mask for power-of-two epochs.
- `lwma` — `lwma_next_difficulty(timestamps, difficulties, T)`: Zawy's LWMA-1,
  exact `u128` integer form. Provably a fixed point on an on-target window; 6T
  per-solvetime clamp, out-of-sequence guard, low-L clamp (rise capped ≈10×
  window-average), result floored at 1.

### `qlab-devnet` integration (PoW module only)

- `pow.rs` — `PowEngine::pow_hash(&self, header, seed)` gains the RandomX key
  (the key-block hash). `RandomXPow` adapter (RandomX over the header preimage,
  keyed by the seed). `KeccakPow` **ignores** the seed → byte-identical to M6, so
  every M6 test remains a valid regression guard.
- `validation.rs` — `expected_difficulty` now runs **LWMA-120** over the trailing
  window; `pow_seed(chain, parent, height, schedule)` resolves the key-block seed
  by walking the branch; the PoW check hashes under it.
- `mining.rs` / `node.rs` — the seed threads from the chain through `mine` and the
  validation self-check; `SimConfig` gains `key_epoch_blocks` / `key_epoch_lag`
  (sim knobs; a tiny epoch exercises rotation in tests).
- `params_devnet.rs` — swapped the old Bitcoin-style sliding-window constants for
  `LWMA_WINDOW_BLOCKS = 120`, `SEEDHASH_EPOCH_BLOCKS = 2048`,
  `SEEDHASH_EPOCH_LAG = 64`, plus `POW_TARGET_BLOCK_TIME_SECS = 75`.

## Parameter freeze status (explicit)

| Parameter | Value | Status |
|---|---|---|
| Target block time `T` | **75 s** | **FROZEN** (consensus-parameters §2) |
| LWMA window `N` | 120 | **testnet-tunable, NOT frozen** (protocol-spec §10 → v1.1) |
| LWMA clamps (6T, low-L, floor) | Zawy LWMA-1 | **NOT frozen** |
| Key-block epoch / lag | 2048 / 64 | **NOT frozen** (Monero provenance) |

The devnet sim drives LWMA with the accelerated `SimConfig::block_time_secs`, not
75 s — same algorithm, different `T`. Provenance (Monero/Zawy) is quoted, not
proposed as a Qumbra value.

## Design decisions (defaults; flag for coordinator if steering)

- **Scalar difficulty kept.** The RandomX 256-bit hash reduces to the existing
  devnet scalar model (leading 8 bytes ≤ `u64::MAX / difficulty`); LWMA retargets
  that scalar, which doubles as the heaviest-chain weight. A full 256-bit target
  is a later, cosmetic change.
- **`qlab-pow` has no workspace deps**; the `PowEngine` adapter lives in
  `qlab-devnet` (no dependency cycle).
- **Light mode only** (256 MiB cache, no 2 GiB dataset) — RandomX output is
  identical to fast mode, so vectors match; keeps the workspace suite's RAM sane.

## Behavioral change worth noting

Under LWMA the per-block difficulty varies with cadence, so "a longer branch" no
longer implies "a heavier branch". The node-level fork-choice test was rewritten
to extend the competing branch until its cumulative work actually overtakes the
incumbent, then assert the reorg — the heaviest-chain property itself is unchanged
(and still directly tested in `chain.rs` with explicit difficulties).

## Tests

- `qlab-pow`: 25 unit tests (4 RandomX vectors/determinism, 11 keyblock, 10 LWMA).
- `qlab-devnet`: 104 lib tests (all M6 tests preserved) + 3 RandomX e2e integration
  tests (`tests/randomx_e2e.rs`): real-RandomX mine→validate→peer-revalidate,
  key-block seed rotation, and seed-sensitivity of the RandomX output.

## Reproduction

- Rig: Apple M-series, macOS (Darwin 25.5); `randomx-rs 1.4.1` builds with
  `cmake` + clang, recommended flags `FLAG_HARD_AES | FLAG_JIT | FLAG_SECURE`.

### Runs (this session, `--release` unless noted)

| Suite | Result |
|---|---|
| `qlab-pow` | **25 passed** (RandomX vectors/determinism, keyblock, LWMA) |
| `qlab-devnet` lib | **104 passed** (all M6 tests preserved) |
| `qlab-devnet` `tests/randomx_e2e` | **3 passed** (mine→validate→peer-revalidate, rotation, seed-sensitivity) |
| `qlab-demo` (debug; real M3 proofs) | **5 passed** (whole-stack composition) |
| `qlab-bench m6devnet` | **1 passed** (the qlab-bench module that drives the devnet) |

### Full-suite acceptance — deferred to the coordinator (explicit)

The full unfiltered `cargo test --release -p qlab-bench` bar (bench discipline §5)
was **NOT** run this session, deliberately: session **N2 was concurrently running
an RSS-sensitive `qlab-bench` release measurement** and the 36 GiB machine was
already at ~12 GB swap. The m4gate leaf/interior proves reach ~13–30 GB each;
running a second heavy suite would have OOM/swapped both sessions and corrupted
N2's peak-footprint numbers.

This is safe to defer because **this diff is orthogonal to the AIR / m4gate** —
verified boundary-clean (`git diff --name-only main...HEAD` touches only
`qlab-pow`, `qlab-devnet`, the workspace manifest/lock, and this doc; **zero**
`qlab-bench`/`m4gate` files). The only qlab-bench code exercising this change is
the `m6devnet` module, which passed. Coordinator to run the full unfiltered
qlab-bench acceptance on a quiet machine.
