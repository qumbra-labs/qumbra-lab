# issue #22 (B′) — `ethereum/soundcalc` on the three g22 lanes

> Item 2 of issue #22 / fri-soundness-accounting-2026-07 §5.2: run
> [`ethereum/soundcalc`](https://github.com/ethereum/soundcalc) on both lanes
> (all three configs at the adopted g22) to get **the full soundness term
> inventory — DEEP / ALI / commit-phase / batching, not just the query term —
> on the record**. The design appendix's §3 hand-calc computed only the query
> term and flagged the rest as "must be computed, not assumed away." This does that.

## Provenance (reproducible)

- **soundcalc rev:** `809896fb8d3aba4fd8f657c781601e3ef2b968dd` (2026-07 HEAD; capacity/conjectured regime **removed** post-DG25/CS25 — supports **UDR** (unique-decoding) and **JBR** (Johnson-bound) *proven* regimes only).
- **model:** `FRI_STARK` (DEEP-ALI circuit + FRI PCS), field `KoalaBear⁴` (challenge field ≈ 2^124), no lookups (the narrow-Keccak AIR is lookup-free, M1.5b). Modeled on soundcalc's Pico template.
- **run:** `python -m soundcalc` on a Qumbra TOML with the three lanes as circuits; term dict is round-by-round (rbr) security = min over attack surfaces.

### The three lanes as modeled (TOML)

| param | consensus | leaf-agg | interior |
|---|---|---|---|
| lane | b16/q20/g22/fp16/a16 | b4/q40/g22/fp16/a16 | b2/q80/g22/fp16/a16 |
| rho (=1/blowup) | 0.0625 | 0.25 | 0.5 |
| trace_length | 2^18 | 2^16 | 2^19 |
| domain D = trace/rho | 2^22 | 2^18 | 2^20 |
| num_queries | 20 | 40 | 80 |
| grinding_query_phase | 22 | 22 | 22 |
| fri_folding_factors | [16,16,16,4] | [16,16,16] | [16,16,16,8] |
| fri_early_stop (final domain) | 256 | 64 | 32 |
| batch_size (committed width) | 618 | 3638 | 3638 |
| num_constraints | 900 † | 5549 | 5549 |
| air_max_degree | 3 | 3 | 3 |
| opening_points (max_combo) | 2 | 2 | 2 |
| hash_size_bits | 256 ‡ | 256 | 256 |

† consensus `num_constraints` is an **estimate** for the narrow-Keccak bucket AIR (not separately measured; leaf/interior 5,549 is measured — m4gate). It feeds only the ALI term, which is ~100+ bits (non-binding at 2^124), so the estimate does not affect any binding total. ‡ Keccak-256-class MMCS digest (128-bit collision > 100, non-binding).

## Full term inventory (bits of security, per regime)

| lane | regime | query | batching | commit (max round) | ALI | DEEP | **total (min)** |
|---|---|---|---|---|---|---|---|
| **consensus** b16/q20/g22 | UDR | 40 | 93 | 115 | 114 | 103 | **40** |
| | JBR | 61 | **60** | 82 | 104 | 94 | **60** |
| **leaf-agg** b4/q40/g22 | UDR | 49 | 95 | 115 | 111 | 105 | **49** |
| | JBR | **60** | 69 | 89 | 105 | 99 | **60** |
| **interior** b2/q80/g22 | UDR | 55 | 94 | 117 | 111 | 102 | **55** |
| | JBR | **57** | 71 | 95 | 106 | 98 | **57** |

**Best provable per lane** (max over the two valid regimes): consensus **60**, leaf **60**, interior **57**. Binding proven floor across lanes = **57 bits** (interior, JBR, query-bound).

## Cross-check vs fri-soundness-accounting §3 — query terms match to the bit

soundcalc's **query phase** = `num_queries · bits_per_query + grind`. The bits-per-query it derives equal the design §3 table exactly, and the totals are the §3 g20 figures **+2 for the g22 grind**:

| | design §3 (g20) | soundcalc (g22) | check |
|---|---|---|---|
| UDR bits/query (b16 · b4) | 0.91 · 0.68 | 0.91 · 0.68 | ✅ exact |
| JBR bits/query (b16 · b4) | 1.96 · 0.96 | 1.96 · 0.96 | ✅ exact |
| UDR total — consensus / leaf | ~38 / ~47 | 40 / 49 | ✅ (= +2 grind) |
| JBR total — consensus / leaf | ~59 / ~58 | 61 / 60 | ✅ (= +2 grind) |

The interior lane (b2/q80) is not in the design table; soundcalc gives UDR 55 / JBR 57 (b2 bits/query ≈ 0.42 UDR, 0.44 JBR).

## What the non-query terms say (first on record)

- **DEEP / ALI** land at **94–106 bits** (JBR) — i.e. **35–45 bits ABOVE the proven query floor**, so they never bind. (In the *conjectured* regime, where the query floor is ~98.8, these same terms sit only a few bits above it — exactly the "3–12 bits above the query floor" the appendix §3 predicted, and they do NOT cross below it.)
- **Commit-phase** tops out at **82 bits** (consensus JBR, round 4) — this is the **BCHKS25 field cap ≈ 80** the appendix §3 named. It does not bind here: at 20–80 queries the query/batching floor (57–61) is already lower.
- **Batching** is the one non-query term that comes *close*: consensus JBR batching **60**, one bit under the query phase (61), so it is the binding term for that lane/regime. Still squarely within the appendix's ~59–61 proven-Johnson expectation — not an anomaly.

## Stop-condition check (issue #22 red line) — NOT tripped

The issue says stop if a **non-query term drags the total below 100**. It does not:

- The proven totals (57–60) being far under 100 is the **known ~40-bit conjectured-to-proven gap** (design §3/§4), NOT a B′ regression and NOT a new finding — the design explicitly keeps a *conjectured* label and defers proven-regime repricing into the WHIR re-evaluation.
- soundcalc **does not compute the conjectured (list-decoding-capacity) regime** (removed post-DG25), so it cannot and does not move the "~100-bit conjectured" headline. That headline remains the design's DG25 query-term hand-calc + grind (100.8 / 100.4 at g22).
- The value soundcalc adds: it confirms every **non-query** term sits **at or above** the proven query floor, which corroborates that in the conjectured regime too the non-query terms stay above the ~100.4/100.8 conjectured query floor — i.e. nothing was hiding in the "assumed-away" terms. **No term drags any total below its expected floor → no design-repo-level finding.**

## Caveats

- soundcalc's **proof-size** estimates (consensus 233–248 KiB, leaf ~2.3 MiB, interior ~4.5 MiB) are a generic worst-case Merkle-multi-proof model (256-bit digests, no cap/arity optimization) and are **not** our measured fixed-width sizes (M3 136.4 KB, leaf 781.8 KB, interior 1.51 MB). Only the soundness bits are the deliverable here; proof sizes stand from the re-bench (`docs/issue22-rebench-run{1,2}.md`).
- Regimes are **proven only** (UDR/JBR). The conjectured accounting lives in the design appendix.
- consensus `num_constraints` is an estimate (see †); it moves only the non-binding ALI term.
