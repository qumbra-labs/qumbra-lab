# M-WHIR step 0 — soundcalc WHIR parameter derivation (both points)

> Task 3 of the M-WHIR step-0 baton (whir-reevaluation §5). Derive two WHIR
> parameter points for the **real M3 consensus statement** (2^18 × 618), commit
> their full soundness term inventories, and **confirm/refute** the re-evaluation
> doc's "[derived] degree-4 provable cap ≈ 80 bits". EXPERIMENT branch —
> measurement only, no adoption verdict.

## Provenance (reproducible)

- **soundcalc rev:** `809896fb8d3aba4fd8f657c781601e3ef2b968dd` (2026-07 HEAD — same
  rev the FRI issue-#22 run used; capacity/CBR regime **removed** post-DG25/CS25,
  so it reports the **proven** regimes only: UniqueDecoding (UDR) and
  JohnsonBound (JBR)). WHIR support: `soundcalc/pcs/whir.py`, following the
  WizardOfMenlo/stir-whir-scripts reference; round-by-round (rbr) security =
  min over all attack-surface terms.
- **field:** `KoalaBear^4` (challenge ≈ 2^124) for point (i); `KoalaBear^5`
  (quintic X^5+X^2−1, |EF| ≈ 2^154.6) for point (ii). soundcalc had no
  `KoalaBear^5` entry — added as a calculator constant (field size only; **not**
  a field-arithmetic impl — the p3 0.6.2 `QuinticTrinomialExtensionField` already
  exists, so STOP-POINT C did not trigger).
- **statement modeled:** `log_degree = 18` (2^18 trace rows), `batch_size = 618`
  (committed main-trace width, M3 final), `air_max_degree = 3`, `opening_points =
  2` (local + next-row), `num_constraints = 900` (narrow-Keccak bucket estimate;
  feeds ALI only — non-binding). WHIR PCS: 4 iterations, folding `[4,4,4,4]`
  (m: 18→2), starting rate 1/16 (log_inv_rate 4 ⇒ initial LDE |L| = 2^22).
- inputs: `soundcalc/zkvms/qumbra_whir/{deg4,deg5}.toml` (in the step-0 scratch
  copy of soundcalc; parameters reproduced in-line below).

> **Modeling note — why batched columns (not one flat multilinear).** A single
> flattened multilinear of the whole trace would be 2^18·618 ≈ 2^27.3 variables.
> That is **impossible on KoalaBear**: 2-adicity 24 caps any evaluation domain at
> 2^24, so even at rate 1/2 the largest committable multilinear is 2^23. Hence the
> only 2-adically-feasible representation is the same one FRI uses — 618 column
> multilinears of 2^18 each, Merkle-batched by row (`batch_size = 618`,
> `log_degree = 18`). Every number below is under that (forced) modeling.

## Grinding used

`grinding_bits_queries = 22` per iteration and `grinding_batching_phase = 22`
(matches the adopted g22 lane); folding-phase grinding set high only to keep those
terms non-binding while probing. **Grinding does not affect proof bytes** (nonce),
so the proof-size column is grind-independent; grind affects prove-time only.

## Point (i): degree-4 — the proven-Johnson CEILING (the ~80-bit cap)

`field=KoalaBear^4, rate 1/16, folds [4,4,4,4], q=[40,32,26,23], ood 2, g22`

| term (JBR, bits) | value | | term | value |
|---|---|---|---|---|
| **batching** | **82** | | Shift(i=1) | 101 |
| fold(i=0,s=1..4) | 92–95 | | fold(i=1,s=1..4) | 87–90 |
| OOD(i=1..3) | 196–200 | | fold(i=2,s=1..4) | 84–87 |
| Shift(i=2) | 125 | | **fold(i=3,s=1)** | **80** |
| Shift(i=3) | 122 | | fold(i=3,s=2..4) | 81–83 |
| fin | 171 | | ALI | 104 |
| DEEP | 94 | | **JBR total** | **80** |

UDR total at this (sane) query count = **44**.

**Query count cannot break the cap.** Sweeping queries at deg-4:

| queries (per iter) | JBR total | UDR total | note |
|---|---|---|---|
| [20,16,13,11] | 61 | 32 | under-queried |
| [40,32,26,23] | **80** | 44 | |
| [80,64,52,45] | **80** | 66 | |
| [120,100,80,70] | **80** | 91 | proof ~4 MB |
| [200,150,120,100] | **80** | 103 | proof ~7.7 MB (absurd) |

JBR **saturates at exactly 80** — the binding terms (`batching` 82,
`fold(i=3,s=1)` 80) are field/last-domain-limited (∝ n/|F|), independent of query
count. UDR only climbs past 80 by paying hundreds of queries (multi-MB proofs)
and is the weaker regime for correlated-agreement. **The practical proven-Johnson
ceiling at degree-4 for our statement is 80 bits.**

### ✅ VERDICT: the re-evaluation doc's "[derived] degree-4 provable cap ≈ 80 bits" is CONFIRMED
Not refuted, and to the bit: soundcalc's WHIR JBR analysis at |F|≈2^124 / 2^22-class
domain gives **exactly 80**. This is the same wall the fri-soundness appendix §3
records for FRI ("caps proven-Johnson near ~80 bits at 2^22+-class LDE sizes
regardless of query count") — confirming §1.2's claim that **the cap is a property
of the degree-4 field, not of the PCS** (FRI and WHIR hit the same ~80).

## Point (ii): degree-5 (quintic) — Johnson-PROVEN 100

`field=KoalaBear^5, rate 1/16, folds [4,4,4,4], q=[40,32,26,23], ood 2, g22`

| term (JBR, bits) | value | | term | value |
|---|---|---|---|---|
| **batching** | **111** | | Shift(i=1..3) | 101–151 |
| fold(i=0,s=1..4) | 122–125 | | fold(i=1,s=1..4) | 118–121 |
| OOD(i=1..3) | 258–262 | | fold(i=2,s=1..4) | 115–118 |
| fin | 171 | | **fold(i=3,s=1)** | **111** |
| ALI | 135 | | DEEP | 125 |
| | | | **JBR total** | **101** |

UDR total = 44 (unique-decoding is far weaker here; JBR is the operative proven
regime — Haböck 2025/2110 proved mutual correlated agreement to the Johnson bound).

Minimal-query search (JBR ≥ 100):

| queries | JBR total | proof worst / expected |
|---|---|---|
| [36,29,23,20] | 93 | 1426 / 1408 KiB |
| **[40,32,26,23]** | **101** | **1585 / 1564 KiB** |
| [44,35,28,25] | 109 | 1743 / 1719 KiB |
| [48,38,31,27] | 111 | 1901 / 1874 KiB |

So the degree-5 (quintic) extension **lifts the proven-Johnson ceiling from 80 to
100+** on the identical statement — the +31 bits of field headroom (2^124→2^155)
push every field-limited term (batching, last-fold) above 100. This is the
PSE / lean-Ethereum precedent, and confirms §1.2/§3.1: **proven-100 on this field
family requires the quintic extension.**

## The proof-size surprise (bears directly on the pre-registered criterion)

soundcalc's WHIR proof-size **estimate** for our statement at the JBR-100/deg-5
point is **~1.56 MB (expected)** — about **11× the 136.4 KB target** and ~10× the
150 KB ceiling. Neither field nor query-tuning fixes it:

- Fatter folds make it *worse*: folds [6,6,6] → 6.1 MB; [9,9] → 48 MB (each fold
  ships 2^k sibling values/query). `[4,4,4,4]` is near-optimal.
- Lower starting rate (WHIR's memory sweet-spot) does *not* help size: rate 1/4
  needs more queries → 3.1 MB. Rate 1/16 is the smallest.
- deg-4 at the same query count is the same ~1.56 MB (size is query-driven, not
  field-driven).

**Why:** WHIR's query cost scales with the committed *width*. Our M3 statement is
**wide-and-short** (618 columns × 2^18) — WHIR's anti-sweet-spot: each of ~120
total STIR queries opens a 618-wide leaf, across 4 re-committed iterations, plus
per-round OOD and sumcheck messages. This is exactly why PSE's shipped Keccak-WHIR
proof was only 54 KB — that was a **Spartan single-multilinear**, not a 618-column
uni-stark trace. The two are not comparable, as §1.3 already flagged.

**Caveats (do not over-read this number):**
1. soundcalc's proof size is a rough Merkle-path count (its README: "only an
   estimate … to get the actual proof size you need to run the actual prover").
   It will not be 10× wrong, but ±30% is plausible.
2. **It says nothing about WHIR's actual selling point — prover MEMORY** — which
   soundcalc does not model and which this baton **cannot measure** (task 2 is
   structurally blocked; see `mwhir-step0-plan.md`). The design doc's §2 thesis
   was the *memory* horn (~1.3–2.6 GB at rate ½), not proof size.
3. A hypothetical smarter uni-stark→WHIR frontend might commit the constraint
   system as fewer/narrower multilinears; this estimate is under the one natural,
   2-adically-forced modeling. Still, the wide-trace penalty is structural.

## Factual comparison vs the pre-registered criteria (NOT a verdict)

| criterion (whir-reeval §5) | threshold | this derivation |
|---|---|---|
| proof ≤ 136.4 KB (and ≤ 150 KB) | 136.4 KB | **~1.56 MB estimated** — ~11× over (both points; size is query-driven) |
| parameters at soundcalc-verified accounting | — | ✅ done (this doc), proven regimes only |
| proven-100 achievable | — | ✅ only at degree-5 (deg-4 caps at 80) |
| working set ≤ ~3.5 GB | 3.5 GB | **not measurable** — task 2 structural block |
| phone-projected prove ≤ 15 s | 15 s | **not measurable** — task 2 structural block |

The coordinator adjudicates. On the one dimension a paper derivation *can* speak
to — proof size — the wide M3 statement looks adverse for WHIR by ~10×; the
memory dimension, the actual reason WHIR was on the table, remains unmeasured.
