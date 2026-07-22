# qlab-devnet load-test — measured run 1 (issue #42)

The measured basis for the three `[open]` consensus-parameter rows the appendix
defers to M6 devnet load-testing: **§6 block-weight penalty constants**, **§2
coinbase-maturity depth**, **§4 downtime jail threshold**. This run **produces the
data**; each DECISION stays design-side (consensus-parameters). Nothing here is a
proposal — only a data-backed candidate *range* per constant.

Produced by the in-crate runner:

```
cargo run --release -p qlab-devnet --bin load
```

## Environment (bench discipline)

- repo: branch `claude/devnet-load`, sub-phases A–F (`crates/qlab-devnet/src/weight.rs`, `src/load/*`, `src/bin/load.rs`)
- hardware: Apple M5 Max, 36 GiB
- OS: Darwin 25.5.0 (macOS); power: AC
- prover crates: Plonky3-class pinned `=0.6.1` (Cargo.lock) — **not exercised here**: the load sweeps are consensus-sim dynamics, not proving. Zero contact with `qlab-bench` / `m4gate` (issue #42 boundary; conflict-free with the parallel #41 B″ batch).
- **Determinism.** Every scenario draws from a seeded, dependency-free `SplitMix64` (no wall-clock / entropy inputs). Reproduction is therefore **byte-for-byte exact**, not statistical — `run1` and `run2` are `diff`-identical (see `devnet-load-run2.md`). This is a stronger guarantee than the prover-timing runs' "reproduced twice within jitter".

## Sim inputs — DECIDED design values (sourced), not placeholders

| Input | Value | Source |
|---|---|---|
| Block time | 75 s | consensus-parameters §2 (B2) |
| Blocks/day (= epoch) | 1,152 | derived; = §4 epoch |
| Launch emission | 57,600 QMB/day (r0 = 50 QMB) | consensus-parameters §2/§5 |
| Tail reward | 1.22441 QMB/block (≈1,410 QMB/day) | consensus-parameters §2 (derived tail) |
| Fee floor | 0.01 / 0.02 / 0.04 QMB (2×2/4×4/8×8) | consensus-parameters §5 |
| 2×2 tx weight | 136 KiB (measured M3 fixed-width) | prototype-bench §10 / m6-devnet runs |

The *swept* quantities — weight-governor constants, coinbase maturity, jail grid —
are the `[open]` questions. Weight-governor placeholder defaults live bannered in
`params_devnet` (`WEIGHT_*`); all are tunable via `weight::WeightParams`.

---

## 1. Spam-flood: block-weight governor response (§6)

**Model (deterministic).** All spam is 2×2 (the worst-case bytes-per-fee vehicle).
Each block a *myopic-rational* miner fills to `b*` where marginal fee = marginal
penalty: `b* = M + fee·M²/(2·base·w)`, clamped to `[M, 2M]` (`M` = effective
median = penalty-free zone; `w` = per-tx weight; `base` = block base reward). The
miner never fills past `b*` (penalty on the base reward outweighs the extra fee);
the attacker's budget (= `k ×` daily emission, the Rucknium native anchor) caps
affordable bytes. Realized weights feed the two-median governor; we read the
steady state over a 30-day sustained flood.

### 1a — S0 devnet-default (10 MB free zone, lt-cap 1.4×, st-cap 50), **launch**

| budget ×emission | chain growth MB/day | median growth ×start | final median MB | attacker cost %emission | bounded? |
|---|---|---|---|---|---|
|  0.5× |   383,027 |  34.9 |   332 |   50.0 | NO |
|  1.0× |   766,055 |  69.7 |   665 |  100.0 | NO |
|  2.0× | 1,532,109 | 139.5 | 1,330 |  200.0 | NO |
|  5.0× | 3,830,273 | 348.6 | 3,325 |  500.0 | NO |
| 10.0× | 7,660,547 | 697.3 | 6,650 | 1000.0 | NO |

### 1b — S0 devnet-default, **tail** era

| budget ×emission | chain growth MB/day | median growth ×start | final median MB | attacker cost %emission | bounded? |
|---|---|---|---|---|---|
|  0.5× |   9,376 |  1.00 |   9.5 |  49.8 | yes |
|  1.0× |  18,752 |  1.71 |  16.3 |  99.7 | yes |
|  2.0× |  37,505 |  3.41 |  32.6 | 199.4 | NO |
|  5.0× |  93,762 |  8.53 |  81.4 | 499.2 | NO |
| 10.0× | 187,524 | 17.07 | 162.8 | 999.2 | NO |

### 1c — constant-set comparison @ 5× emission, launch, 30-day flood

| constant set | chain growth MB/day | median growth ×start | final median MB | cost %emission |
|---|---|---|---|---|
| S0 devnet-default (10 MB free, 1.4×, st50) | 3,830,273 | 348.6 | 3,325 | 500.0 |
| S1 small-free-zone (2 MB)                  | 1,783,576 | 520.4 | 1,041 | 232.8 |
| S2 long-window 50k (creep damper)          | 3,830,273 | 209.2 | 1,995 | 500.0 |
| S3 tight-lt-cap (1.2×)                      | 3,830,273 | 348.6 | 3,325 | 500.0 |
| S4 loose-lt-cap (2.0×) + st200             | 3,830,273 | 348.6 | 3,325 | 500.0 |

### 1d — governor-OFF baseline (no penalty, no cap), launch

| budget ×emission | chain growth MB/day |
|---|---|
|  0.5× |   383,027 |
|  1.0× |   766,055 |
|  5.0× | 3,830,273 |
| 10.0× | 7,660,547 |

### Findings (§6)

1. **The two-median governor is demand-adaptive and does NOT bound a budgeted
   flood.** At launch the governed chain growth (1a) is *identical* to the
   governor-OFF baseline (1d) at every budget — the quadratic penalty starts at
   zero *slope* just above `M`, so a myopic-rational miner keeps accepting
   slightly-larger blocks and the effective median ratchets up to exactly the
   attacker's sustainable byte-rate. Attack cost is simply the fee bill
   (`cost %emission == budget ×100%`).
2. **The binding anti-spam control is the fee floor (§5), not the weight
   governor.** This *reinforces* §5's already-decided high floor: at 0.01 QMB/tx,
   emission-scale money still buys enormous byte volume (0.5× emission ⇒ ~374
   GB/day). The governor cannot rescue a too-low fee — it adapts to whatever
   demand pays for.
3. **What the governor *does* buy:** (a) the hard `2M` cap prevents single-block
   gigantism (always holds — the one unconditional bound); (b) `long_window` damps
   the transient ramp and sustained creep — S2 (50k window) cuts median growth
   348× → 209× vs S0 (5k). `st_cap` and `lt_cap` (S3/S4) barely move the
   budgeted-flood outcome; they only shape transient-surge accommodation.
4. **The governor's grip weakens as emission decays.** Because the penalty scales
   with the base reward, the tail era (1b) gives more ground per fee — but the
   *budget anchor* also shrinks with emission, so at low tail budgets (≤1×) the
   10 MB free zone actually holds (bounded, growth 1.0×). This matches §5's "cost
   rises monotonically as emission decays" from the opposite direction: the
   governor is most adaptive (weakest) exactly when the fee is most binding.

**Data-backed candidate ranges (§6 — decision design-side):**
- `max_multiple = 2` (Monero) — keep; the one hard bound that always holds.
- `min_weight` (free zone) = size to organic capacity: launch ~1 TPS × 75 s ×
  136 KiB ≈ **10 MB** is a sound floor; larger free zones are cheaper to bloat.
- `long_window` = the creep damper: a devnet-scaled 5k is **too small**; use
  **tens of thousands of blocks (weeks-scale)**, toward Monero's 100k (≈87 days at
  75 s) — the flood then never turns the long window over, strongly damping creep.
- `lt_cap ≈ 1.4×`, `st_cap ≈ 50` (Monero) — low sensitivity for sustained abuse;
  keep absent a surge-accommodation reason.
- **Headline for the appendix:** §6's constants are a *backstop* (anti-gigantism +
  surge-damping); the anti-spam load is carried by the §5 fee floor. This is the
  measured correction owed to any reading of §6 as the primary spam bound.

---

## 2. Reorg-depth in degraded mode (§2 coinbase maturity)

**Model.** Ebb-and-Flow degraded mode = committee stalled = no finality ⇒ pure
heaviest-chain PoW (the `ChainState` fork-choice with no finalized head — the
model's depth semantics are grounded against it in a test). An adversary with
hashrate fraction `q < ½` privately mines an alternate branch; on a strict
overtake it publishes, rolling back the honest suffix (the reorg depth). Seeded
Monte-Carlo; the table reports the **deepest** reorg over patience bands
`{6, 20, 50}` and 24 seeds (a conservative, attacker-optimized bound).

| adversary q | 6h stall | 24h stall | 30d stall (pathological) |
|---|---|---|---|
| 0.10 |  2 |   2 |   5 |
| 0.20 |  9 |  11 |  14 |
| 0.30 | 15 |  18 |  27 |
| 0.40 | 30 |  43 | 118 |
| 0.45 | 71 | 209 | 330 |

Depth distribution detail (24h stall, giveup 20):

| q | reorgs/1000 blk | mean depth | p99 depth | max depth |
|---|---|---|---|---|
| 0.10 |  0.87 |  2.0 |   2 |   2 |
| 0.20 |  3.47 |  3.0 |   9 |   9 |
| 0.30 |  5.21 |  4.7 |  13 |  13 |
| 0.40 |  7.81 |  7.0 |  43 |  43 |
| 0.45 | 18.23 | 14.2 | 117 | 117 |

Natural propagation orphans at 75 s (honest-only baseline):

| propagation τ | orphan rate/block | P(depth ≥ 2) |
|---|---|---|
|  1 s | 0.0132 | 1.75e-4 |
|  2 s | 0.0263 | 6.92e-4 |
|  5 s | 0.0645 | 4.16e-3 |
| 10 s | 0.1248 | 1.56e-2 |

### Findings (§2)

1. **Realistic adversaries stay well under 100 blocks.** `q ≤ 0.30` never exceeds
   **27** even over a pathological 30-day stall; `q ≤ 0.40` stays **≤ 43** at
   realistic (≤ 24 h) stall durations. A ~100-block maturity (≈ 2.1 h at 75 s)
   comfortably covers these — matching §2's stated "~100 blocks (≈ 2 h)".
2. **Maturity cannot bound the `q → ½` / long-stall tail — that is finality's
   job.** `q = 0.40` reaches **118** over a 30-day stall; `q = 0.45` breaks 100
   already at 24 h (**209**) and hits **330** at 30 d. Reorg depth is unbounded as
   `q → ½` over unbounded time; no maturity depth can cover it. Degraded mode is
   designed to be *short-lived* (finality resumes on committee recovery), so the
   operative durations are hours, not weeks.
3. **Natural orphans are shallow.** At a sub-10-s propagation budget (consensus
   §7) the honest-only orphan rate is a few percent and depth ≥ 2 is `(τ/T)²`-rare
   — the healthy degraded-mode reorg is depth-1.

**Data-backed candidate range (§2 — decision design-side):** coinbase maturity in
**~100–150 blocks** (≈ 2.1–3.1 h at 75 s): ~100 covers realistic adversaries
(`q ≤ 0.40`) at realistic stalls with margin; ~150 additionally covers `q = 0.40`
over a pathological 30-day stall (118). Beyond ~150 has diminishing returns
(only helps against the `q → ½` regime that finality, not maturity, must address)
while delaying coinbase spendability. The §2 "~100 blocks" figure is **validated
as the right order of magnitude.**

---

## 3. Downtime jail threshold (X%, Y-block) (§4)

**Rule (Cosmos shape).** Jail the moment a validator's *missed* count over the
trailing `Y`-block window exceeds `(1−X)·Y` (signed fewer than `X` of the last
`Y`). No-slash (committee-governance §3); maps onto `CommitteeState::jail`
(grounded in a test). Detection lag for a fully-dark validator is deterministic:
`⌈(1−X)·Y⌉` blocks. False-jail rate (a validator with acceptable uptime tripped at
least once) is Monte-Carlo over N=21 validators × 8 epochs.

| X (signed ≥) | Y window | detection lag (blk / wall) | false-jail @99% | @99%+2% blips |
|---|---|---|---|---|
|  5% |  50 |  48 / 1.0 h | 0 | 0 |
|  5% | 100 |  95 / 2.0 h | 0 | 0 |
|  5% | 288 | 274 / 5.7 h | 0 | 0 |
|  5% | 576 | 548 / 11.4 h | 0 | 0 |
| 10% |  50 |  45 / 56 m | 0 | 0 |
| 10% | 100 |  90 / 1.9 h | 0 | 0 |
| 10% | 288 | 260 / 5.4 h | 0 | 0 |
| 10% | 576 | 519 / 10.8 h | 0 | 0 |
| 33% |  50 |  34 / 42 m | 0 | 0 |
| 33% | 100 |  67 / 1.4 h | 0 | 0 |
| 33% | 288 | 193 / 4.0 h | 0 | 0 |
| 33% | 576 | 386 / 8.0 h | 0 | 0 |
| 50% |  50 |  25 / 31 m | 0 | 0 |
| 50% | 100 |  50 / 1.0 h | 0 | 0 |
| 50% | 288 | 144 / 3.0 h | 0 | 0 |
| 50% | 576 | 288 / 6.0 h | 0 | 0 |

False-jail onset as uptime degrades (independent misses):

| uptime | X5%/Y100 | X10%/Y100 | X33%/Y100 | X50%/Y100 | X50%/Y50 |
|---|---|---|---|---|---|
| 99% | 0 | 0 | 0 | 0 | 0 |
| 97% | 0 | 0 | 0 | 0 | 0 |
| 95% | 0 | 0 | 0 | 0 | 0 |
| 90% | 0 | 0 | 0 | 0 | 0 |
| 80% | 0 | 0 | 0 | 0 | 0 |
| 70% | 0 | 0 | 0 | 0.048 | 0.571 |

### Findings (§4)

1. **False jails are a non-constraint at named-entity uptimes.** At the realistic
   99 % uptime *no* swept `(X, Y)` — including the strictest `X = 50 %` — ever
   falsely jails, even under a 2 % correlated-blip stress. The onset table shows
   the rule stays clean down to **80 % uptime**; only a genuinely-degraded 70 %
   operator under `X ≥ 50 %` / small `Y` gets jailed (which is arguably correct).
2. **So `(X, Y)` is chosen purely for detection speed.** Detection lag =
   `⌈(1−X)·Y⌉`: lower `X` and larger `Y` slow it. The whole grid detects a dark
   validator within 31 min – 11.4 h.

**Data-backed candidate range (§4 — decision design-side):** because false jails
are a non-issue at realistic uptime, pick for detection speed with the epoch as
the scale anchor (§4: "set with epoch length" = 1,152). **`X ∈ [10 %, 33 %]`,
`Y ∈ [100, 288]`** gives detection in **~1.4–5.4 h** with zero false-jail risk to
80 % uptime; a balanced point is **`X ≈ 33 %`, `Y ≈ 100`** (67-block ≈ 1.4 h
detection, huge margin). The Cosmos-lenient `X = 5 %` end is safe but slow
(2–11 h detection) with no false-jail benefit over the stricter cells at these
uptimes.

---

## Summary — candidate ranges (all decisions design-side)

| §  | `[open]` constant | Data-backed candidate range | Key finding |
|----|---|---|---|
| §6 | Block-weight penalty constants | `max_multiple = 2`; `min_weight ≈ 10 MB` (organic capacity); `long_window` weeks-scale (≥ tens of thousands of blocks); `lt_cap 1.4×`, `st_cap 50` (Monero) | Governor is demand-adaptive — a backstop, **not** the primary spam bound; the **§5 fee floor** carries anti-spam. |
| §2 | Coinbase maturity depth | **~100–150 blocks** (≈ 2.1–3.1 h) | Covers realistic adversaries (`q ≤ 0.40`) at realistic stalls; the `q → ½` tail is finality's job, not maturity's. |
| §4 | Downtime jail threshold | **`X ≈ 10–33 %`, `Y ≈ 100–288`** (detection ~1.4–5.4 h) | False jails are a non-constraint to 80 % uptime; pick for detection speed. |

## Reproduction

Re-run `cargo run --release -p qlab-devnet --bin load` — output is **byte-for-byte
identical** (deterministic seeded sims). Confirmed in `devnet-load-run2.md`.
Machinery + sims are covered by the unfiltered `cargo test --release -p qlab-devnet`
(**103 tests**: 59 pre-existing + 44 new load/weight, including the mandated
block-weight boundary negatives).
