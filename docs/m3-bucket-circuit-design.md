# M3 — full 2×2 bucket circuit over the narrow-Keccak pipeline (design draft, 2026-07-17)

Statement source: qumbra-design `transaction-model-and-anonymity-set.md` §4–6/§8
(binding spec). Target fixed by the branch-(b) decision: **consensus config
b16/q20/g20/fp16/a16, ≤150 KB proof, ≤3 s laptop prove.** Estimate: 6–12
Claude session-hours. This doc fixes the machinery and the column budget
before implementation; the M3-est mock cell (added to `levers` in this PR)
prices the geometry before any circuit code exists — the M1.5b/step-0
discipline, third time around.

## 1. The statement (2×2 bucket)

Public inputs: `anchor`, `nf[2]`, `cm'[2]`, `fee` (packed into ~100 KoalaBear
public values at ≤16 bits each). Witness per input: note fields
(`value:64b, rkm:256b, ρ:256b, rseed:256b`), `sk`, Merkle path
(32 × 256-bit sibling + path bit); per output: note' fields.

Permutation schedule (Keccak-256 sponge, rate 1088 — every message below
fits one absorb, so **one permutation per hash invocation**):

| piece | perms ×2 inputs/outputs | running total |
|---|---|---|
| input `cm_i = H(note_i)` (~832-bit message) | 2 | 2 |
| Merkle chain: `d_0 = cm_i`, `d_{k+1} = H(mux(b_k; d_k, sib_k))`, `d_32 = anchor` | 64 | 66 |
| key derivation `nk_i = H(sk_i)` + spend-auth `rkm_i = H'(sk_i, div)` | 4 | 70 |
| nullifier `nf_i = H(nk_i ‖ ρ_i)` | 2 | 72 |
| output `cm'_j = H(note'_j)` | 2 | 74 |
| dummy/padding perms (pipeline keeps chaining, unconstrained wiring) | 22 | **96** |

96 perms × 3072 rows/perm = 294,912 rows → **2^19, the same height M1.5b/c
already prove**. Balance (`Σ value_in = Σ value_out + fee`, 64-bit ranges)
is arithmetic over bits the sponge already absorbs — no extra perms.

## 2. Machinery to add to the M1.5c pipeline

The pipeline today chains `state(q+1) = Round(state(q))` unconditionally;
M3 must (i) know each perm's *role*, (ii) inject constructed messages at
perm boundaries, (iii) bind digests to public inputs, (iv) do balance.

1. **Program ring** (the RC-ring trick, scaled up): a ring of **96 packed
   registers** rotating one step per perm boundary (the boundary flag is
   itself the existing 24-block ring pattern), first-row-pinned to the
   program. Slot 0's ~6 role bits (absorb-fresh / merkle-step / bind-anchor
   / bind-nf / bind-cm / dummy) are exposed through bool-checked unpack
   columns. Fully constrained, no preprocessed trace — preprocessed would
   cost ~14 KB of per-query openings again, the ring costs ~9 KB of width.
2. **Effective-input columns `eff[25]`** (the injection point): the round
   input consumed downstream (V-register entry, parity source) becomes a
   materialized `eff` instead of `a`:
   `eff[l] = boundary·msg[l] + (1−boundary)·a[l]`, where at Merkle
   boundaries `msg` lanes 0–3 / 4–7 are the path-bit mux of (digest `a`,
   sibling witness), at absorb boundaries `msg` is witness note-field
   bits, plus the pad10*1 constants; degree ≤ 3 with `eff` materialized
   (the mux cannot ride inside the parity trick unmaterialized — that
   would hit degree 6).
3. **Witness bit columns (~17, role-multiplexed)**: sibling lanes and
   note-field lanes share columns because their roles never coincide on a
   row; the path bit is one column, held constant within a perm by a
   boundary-gated copy constraint.
4. **Balance accumulator (~2 cols)**: value bits are absorbed bits of the
   cm-perms; a program-flagged accumulator sums `±2^z·eff_bit` across the
   value lanes and must equal the public `fee` at the end. Range = the
   64-bit lanes are bool-checked by construction.
5. **Public binding (~2 cols)**: digest/nullifier/commitment bits at
   program-flagged rows accumulate into packed 16-bit chunks checked
   against the public-value array (uni-stark `public_values`).

**Column budget:** 402 (M1.5c) + 96 (program ring) + ~8 (role unpack +
boundary machinery) + 25 (`eff`) + ~17 (witness lanes) + 1 (path bit) +
~4 (balance + binding accumulators) ≈ **~555 → the M3-est mock is cut at
560 cols × 3072 rows/perm**.

## 3. Step-0 price of that geometry (measured, this PR)

`levers` gains the decided consensus config as a column, a memory guard
(the 560-col × 2^19 × b32 cell OOM-killed the whole run: 36 GB LDE —
guarded analytically now, SIGKILL is uncatchable), and an `--only`
filter. Progress-grade measurements at the consensus config
(publication-grade reproduction comes with the finished circuit):

| point | width | proof KB | prove | note |
|---|---|---|---|---|
| step-1 real AIR (naive 96-col program ring) | 554 | 152.5 | 2.6 s | **over target** — triggered mitigation (i) |
| step-2 real AIR (phase-packed ring + merkle wiring) | 502 | **145.4** | 2.3 s | **PASS both**; diet = −57 cols |
| step-3 budget mock (M3-est) | 520 | 152.6 mock ≈ **147.8 real-adjusted** | — | mock runs ~+4.8 KB vs real at this width |

Mitigation (i) as executed: 3-bit role codes packed 4-per-limb into a
24-col program ring + 4-col phase ring + 12-bit slot-0 decomposition +
materialized role/selector/gate columns (46 cols total vs the naive
102). Cost intuition for step 3: **~0.10 KB per column** at this
geometry — the +18-col step-3 budget spends ~1.9 KB of the 4.6 KB
margin. Banked fallbacks if step 3 overruns: fp32 (~−1–2 KB),
q19/g24 (−6 KB, prove-time variance caveat).

If M3-est lands over 150 KB at the consensus config, the pre-agreed
mitigation order is: (i) width diet (pack the program ring tighter —
96→48 cols at 2 slots/col costs one extra unpack layer), (ii) share
witness/eff columns harder, (iii) only then a design-repo conversation
(the consensus config is a decided parameter now).

## 4. Acceptance gates (unchanged discipline)

1. **Semantics:** a reference transaction circuit in plain Rust
   (extending `qlab-air::reference`) — same notes/paths/keys in, same
   `anchor/nf/cm'` out; negative tests: wrong sibling, wrong path bit,
   wrong `sk`, unbalanced values, replayed nullifier binding.
2. **Size:** ≤ 150 KB at b16/q20/g20/fp16/a16, and within 10% of the
   M3-est mock (re-anchored to realized width if the budget drifts).
3. **Time:** prove ≤ 3 s laptop.
4. **Density:** report realized constraints/row honestly vs the mock.

## 4b. The step-3b margin question (2026-07-17, after step 3a measured)

Structural analysis says the remaining width is irreducible in this
architecture: the two equality banks are a proven minimum (nf consumes two
cross-perm values; their windows nest, so they cannot share a bank), the
bind bank cannot ride the eq banks (windows overlap at arkm's boundary),
and the same-row digest-check trick can eliminate at most one binding that
the schedule already gets for free via chaining. Cards measured and spent:
q19/g24 is dead (prove already 2.9 s; the 2^24 grind would breach the time
gate), fp32 is worth only 0.6 KB. Options for the decision:

1. **Finish 3b and amend the targets to measured reality** — e.g. tx
   ≤ 160 KB, prove ≤ 3.5 s laptop. Both targets are **[assumption]**-flagged
   in performance-budget; the honest arc is 477 KB (M1 stock) → ~151 KB
   (full correct circuit) — a 3.2× real reduction, 1% over an assumed
   round number.
2. **Hunt another −30 cols** (register micro-packing, S/V/U restructuring):
   uncertain payoff, ~2–4 session-hours, architecture risk.
3. **WHIR gate** (already the endgame): rate-1/2 removes the whole
   tension; nothing about this circuit changes.

Recommendation: (1) — finish 3b, measure, and take a small dated
amendment to qumbra-design if the measured full circuit lands over.

## 5. Plan

| step | what | estimate |
|---|---|---|
| 0 | this doc + M3-est mock cell | **done (this PR)** |
| 1 | program ring + `eff` injection + dummy-perm wiring (chain still garbage-correct, tests keep passing) | **done (this PR)** — plus the phase-packing diet after step-1 measured 152.5 KB |
| 2 | Merkle mux + witness lanes + reference node hashing + semantic tests (16-step chain vs reference, corruption negatives) | **done (this PR)** — real AIR 145.4 KB / 2.3 s, both gates green |
| 3a | key/nullifier/cm wiring + the two equality banks + input-chain semantics + bank negative tests | **done (this PR)** — real AIR 563 cols, **148.1 KB / 2.9 s** at consensus (fp32 variant: 147.5) — both gates green with ~1.3% / 3.6% margin |
| 3b | bind accumulators (+16), balance (+~8), outputs + full-tx reference + negatives | ~1–2 session-hours; **projected ~590 cols → ~151 KB / ~3.05 s: both gates hairline-BREACHED** — mitigation (iii) decision needed before or with this step (see below) |
| 4 | bench mode `bucket`, measure vs gates, reproduce, docs + design-repo write-up (EN+ZH) | ~1–2 session-hours |
