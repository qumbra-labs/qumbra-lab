# M1.5b — narrow-Keccak AIR layout design (decision draft, 2026-07-16)

> **M1.5c measured (2026-07-17, runs in `docs/narrow-M15c-run*.md`):** the
> preprocessed iota-RC column is gone. RC[r] is nonzero only at the seven
> z-positions 2^k−1, so each round's constant packs into 7 bits; a ring of
> 24 in-trace registers rotates one step per 128-row block (gated by a
> free periodic flag), R[0]'s bits are exposed through 7 bool-checked
> columns, and the first row pins the ring to the RC table — fully
> constrained, no preprocessed commitment, width 371 → 402. Measured:
> **136.9 KB / 2.0 s at b16/q20/g20/fp16/a16 (reproduced identically —
> the robust double-pass point)**; 130.8 KB at q19/g24 with prove
> 2.2–3.3 s — the 2^24 query grind (~1 s expected, high variance) is
> counted in prove time, so heavy-grind configs trade time variance for
> bytes; 129.0 KB at b32/a16, still RAM-bound on this rig. Net effect of
> M1.5c: **−10 to −13 KB vs M1.5b at every config**, matching the
> predicted trade (+31 cols ≈ +3 KB vs −14 KB of per-query preprocessed
> openings).

> **Implementation-time correction (2026-07-16, v2 — supersedes §2–3 numbers
> below; the implemented AIR in `crates/qlab-air/src/narrow.rs` is the
> authority):** working the schedule row-by-row before coding exposed two
> timing facts the v1 budget missed. (1) **Theta's z−1 parity tap wraps
> across the round** — slice 0 needs C[·][63] of the *same* round, so theta
> cannot start until the whole round input is materialized: a round takes
> **two 64-row windows (128 rows/round, 3072 rows/perm)**, and the C parities
> need their own dual-distance delay register (U, 65 slots + 10 unpack —
> an
> intermediate 296-col revision had wrongly optimized it away by recomputing
> parities at consumption, which misses the z=63→0 seam). (2) **Register slots index by
> remaining-rows-to-consumption**, which shifts every slot count by one vs
> v1. Final geometry: **371 cols × 3072 rows/perm** (a 25 + c 5 + S-unpack
> 25 + ap 25 + x00 1 + S 126 + V 64 + V-unpack 25 + U 65 + U-unpack 10).
> Schedule flags ride **27 periodic columns** (period 128 — free: the
> verifier evaluates them, no commitment, no openings); only the iota round
> constant (period 24 rounds, not a power of two) needs a **1-column
> preprocessed trace** whose per-query opening cost is measured, not
> assumed. The step-0 mock anchor is **P371** in the `levers` mode; the
> real AIR is measured by the `narrow` bench mode against the §4 gates
> (size gate re-anchored to P371 ±10%).

> **Measured outcome (2026-07-17, `narrow` bench mode; runs in
> `docs/narrow-M15b-run*.md`, reproduced across two fresh processes):**
> the implemented 371-col AIR **passes both targets**:
> **141.2 KB / 2.0 s prove at b16/q19/g24/fp16/a16** (exactly 100 bits
> conjectured; 147.7 KB / 1.9 s at the milder q20/g20). Gate verdicts:
> **(1) correctness PASS** — materialized-state chain equals the reference
> permutation (itself cross-checked against p3-keccak), corruption tests
> negative-pass, real-prover roundtrip green. **(2) size MISS-by-1pt as a
> finding**: real AIR = mock + 11.0–11.4% (gate said 10%); the entire gap
> is the preprocessed iota-RC column's per-query opening (~740 B/query —
> measured price of variant (a); the identified fix, an in-trace GF(2) LFSR
> gadget for the RC bits (~+24 cols ≈ +2 KB vs −17 KB of openings), is the
> next optimization, not blocking). **(3) density FINDING**: realized 379
> constraints/row × 3072 rows/perm = 15× the census scaling — the mock's
> density premise was wrong for buildable pipelines, but density affects
> prove time only (1.9–2.1 s, still ≤ 3 s) and no proof-size number relied
> on it. **(4) time PASS** at every b16 config; b32/a16 reaches 139.3 KB
> but proves in 14–28 s on this 36 GiB rig (25 GB LDE swaps — a RAM bound,
> not a compute bound; flagged for the M2 rig).
> The query↔grind trade (q19/g24 at the same 100 bits) is what buys the
> final margin — queries cost ~6.5 KB each at this geometry, grind is a
> one-time prover cost.

Goal: implement **correct** Keccak-f[1600] semantics at a narrow geometry and
confirm measured proof size against the M1.6 mock predictions
(`docs/levers-M1.6-run*.md`). This doc fixes the layout — and states the
honest column budget — before implementation effort is spent. Lab scratch;
the polished outcome goes to qumbra-design after measurement.

**Headline of this draft:** the mock ladder's 41- and 82-col rungs are *not
implementable* under the pinned prover's constraint system (analysis in §2–3).
The realizable point of the family is **~160 cols × 64 rows/round**. That is
fine for the milestone: the step-0 mock cell at exactly that geometry (N160,
added to the `levers` mode in this PR) measures **94.6 KB at the b32/q18/a16
config — inside the ≤150 KB target with 37% margin** (prove 1.05 s). The mock rungs below 160 cols stand as geometry
data points, not buildable layouts; the design-repo write-up's "41–82 cols"
phrasing will need a correction note when M1.5b lands measured numbers.

## 1. The toolbox actually available (pinned Plonky3 0.6.1 — verified in source)

| Facility | Status in 0.6.1 uni-stark | Consequence |
|---|---|---|
| Constraint window | **strictly 2 rows** (`WindowAccess`: `current_slice`/`next_slice` only) | every data dependency must span ≤ 1 row boundary |
| Lookup / permutation argument | **absent** | cross-row re-indexing (rho!) cannot be delegated to a lookup; delayed bits must be carried in columns |
| Preprocessed columns | **present** (`BaseAir::preprocessed_trace`, `prove_with_preprocessed`, reusable `PreprocessedProverData`) | round constants / phase selectors move out of the main trace; commitment is vk-style, but **each FRI query gains one extra BatchOpening** (values + Merkle path) — a real per-query byte cost, must be measured |
| Max useful constraint degree | 3 (stock AIR + mock both use it; quotient = 2 chunks) | keep every gadget ≤ degree 3 so M1.6's geometry calibration transfers |

This toolbox is why the stock AIR is 2,633 cols: with a 2-row window and no
lookups, the whole 1,600-bit round state must be visible inside one window,
and every bit that nonlinearity touches costs a column.

## 2. The honest column budget — z-slice-serial, packed carry

Family: serialize each round over R rows; row j unpacks `zpr = 64/R` z-slices,
runs theta → rho → chi → iota for them, repacks outputs. Carry-only limbs can
pack up to 30 bits/KoalaBear element (they are only ever recomposed linearly);
every bit that theta/chi *touches* must exist as a bool-checked bit column in
the row that touches it.

Cost terms per row (zpr slices; derivation censused against keccak-f):

| # | term | why | cols at zpr=1 (R=64) | cols at zpr=2 (R=32) |
|---|---|---|---|---|
| 1 | packed state carry | round input drains as output fills; sum is a constant 1,600 bits; input/output share columns on a static schedule | 54 | 54 |
| 2 | input unpack (A bits) | theta reads bits | 25 | 50 |
| 3 | theta C, C′ bits | parity via the stock degree-3 trick; D = C′ from slice z−1 = previous row (2-row window ✓) | 10 | 20 |
| 4 | A′ birth bits | rho input; each bit then waits `rot[x][y]` slices | 25 | 50 |
| 5 | rho in-flight store | steady-state alive bits = birth rate × mean delay = 25 × mean(rot) ≈ **680 bits** regardless of zpr (Σ rho offsets = 680, re-census at implementation); packed at 30 bits/col | 23 | 23 |
| 6 | consumption re-unpack | chi at slice z needs 25 A′ bits born in ~14 different earlier rows; they sit packed (term 5) and must be re-unpacked as bits | 25 | 50 |
| 7 | chi/iota outputs | degree-3 expressions of term-6 bits, recomposed linearly straight into output limbs — no extra bit cols | 0 | 0 |
| 8 | phase selectors | preprocessed (variant a): 0 main cols; in-trace rotating flags (variant b): +R | 0 / +64 | 0 / +32 |
| | **total (variant a)** | | **~162** | **~247** |

Two things the M1.5-era intuition missed, recorded for the record:

- **Rho is a 680-bit shift register.** Without lookups, every delayed bit
  occupies column-slots for its whole delay. Packing the shift register (term
  5) is what keeps this survivable, but it forces the re-unpack in term 6 —
  every state bit is unpacked *twice* per round in this family.
- **The carry floor alone (54 cols) exceeds the mock's 41-col rung**, and
  carry + shift register (77) exceeds 82 before a single working bit is paid
  for. The mock's sub-160 rungs measure geometry, not buildable circuits.

## 3. Chosen layout: N160 — zpr=1, 64 rows/round, ~162 cols

- **Geometry:** ~162 cols × 1,536 rows/perm; the 96-perm bucket pads to 2^18
  rows. Config: b32/q18/g10/fp16/a16 (the M1.6 winner).
- **Measured step-0 anchor (this PR's N160 cell):** **94.6 KB** at this
  config (M1.6 context: 82.9 KB @ 164 cols/2^16 rows, 79.6 KB @ 41 cols/2^18
  rows — the extra height doubling costs ~12 KB at 162 cols even with
  arity 16). Prove 1.05 s, verify 3.8 ms. The real AIR is gated against this
  number, which exists before the real AIR does.
- **zpr=1 over zpr=2:** 85 fewer columns for one extra height doubling;
  arity-16 flattened the height cost (M1.6's whole finding), so width wins.
- **z-wraparound at the round seam:** rho reaches back across rounds
  (z − rot mod 64). The in-flight store persists across the seam into the
  next round's rows; the schedule is static, so column assignment is
  compile-time. First and last rounds of a permutation absorb the boundary
  in the trace generator.
- **Degree ≤ 3 everywhere** (bool 2; parity/xor3/chi 3) → same quotient
  shape as mock and stock; calibration transfers.
- **Selector variants**, both behind one flag, both measured as rig cells:
  (a) preprocessed selector columns — expected winner, pays +1 BatchOpening
  per query; (b) in-trace rotating flags (+64 cols → ~226 total) — pays
  width. Measuring (a) vs (b) also prices preprocessed columns for every
  future Qumbra AIR, worth having regardless.

## 4. Acceptance gates (M1.6 rig, same reproduction discipline)

1. **Correctness:** trace generator + AIR against official Keccak-f[1600]
   test vectors (incl. chained permutations), plus corrupted-trace negative
   tests in the `geometry.rs` pattern.
2. **Size:** within **10% of the step-0 mock cell at the same geometry**
   (measured 94.6 KB → gate ≤ 104 KB), selector variant included. If
   preprocessed openings blow the gate, that is a reported finding, not
   silently absorbed.
3. **Density:** realized constraint-evals/perm within 2× of the census
   (76,368); a large excess falsifies the mock's density premise and the
   design repo gets a correction note.
4. **Time:** prove ≤ 3 s laptop (step-0 mock: 1.05 s at this geometry and
   config).

Fallback if the working-column estimate overruns: zpr=2 at ~247 cols
(M1.6 measured 98.0 KB at 330 cols / 2^16 — still ≥ 34% under target), so
the milestone survives a ~50% column-estimate miss.

## 5. Estimate

Step 0 (mock cell at N160 geometry): minutes. Implementation + tests + bench
cells ≈ **4–8 Claude session-hours**; the open-ended part left is the rho
schedule bookkeeping in the trace generator, which is static and unit-testable.
No user-side manual steps.
