# Issue #24 — THREE-binding consolidation: builder findings + D3 spec

Branch: `claude/issue24-bindings` (worktree `../qumbra-lab-issue24`).
Design: ONE msh mechanism (D0), three same-root applications (D1/D2/D3).

## STATUS

- **D0 (msh selector ring) — DONE** (`bd43c4c`). The mechanism.
- **D1 (merge preimage → pv(opvs)) — DONE** (`2dbc4e4`). The ORIGINAL issue #24;
  the PR #23/#25 keccak-preimage-resistance caveat CLOSES (root binding is now
  unconditional / constraint-level).
- **D2 (Σfee rider inputs) — DONE** (`acc9c3c`). The PR #25 boundary CLOSES;
  `interior_epoch_fee_boundary` inverted SAT → UNSAT.
- **D3 (leaf F0 digest input binding + f0dig) — BUILT (2026-07-26,
  `claude/i24-d3-leaf-digest`).** Spec below; it was followed, and it was
  correct. Three notes from the build, for whoever reads this next:
  1. The spec's guess that the OREG/pbit/obit register file is "the likely
     vehicle" was right, and no new register file was needed. The real find is
     that `w0c`/`w1c`/`pbit`/`obit` had been FILLED since inc-4 and constrained
     by nothing — D3 pins them for the first time. A column audit
     (`d3_audit_filled_but_unconstrained_columns`) now reports zero
     filled-but-unconstrained columns in the narrow gate; see its doc comment
     for the method and for the category it CANNOT see.
  2. The dead `shape_mosaic`/`WordBind` table was correct word-for-word,
     including its implicit encoding claim: F0's Pv words need NO `rr` factor
     (the inner PVs ride the outer interface already Monty-encoded), the
     opposite of the D1 merge binding, which hashes canonical u32s. Validated
     against the recorder before anything was built on it
     (`d3_f0_mosaic_matches_the_recorded_transcript`).
  3. `f0dig` needs no carry register — producer and consumer are the same row —
     so the cascade is narrower than the spec feared: `GATE_WIDTH` is unchanged
     (3675), `merge_perms()` is unchanged (53), and the interior rectangle does
     not widen. What moves is only the public-value count: `N_OPVS` 852 → 868.
     The digest is INSERTED between the caps and the inner PVs, not appended,
     so the M3 fee stays the opvs tail (the 棒 3-3 Σfee rider reads it there).

Full unfiltered suite **79/79 green** at every commit; deg ≤ 3 held throughout
(`constraint_degree_within_budget`). Narrow + leaf **byte-identical** (D0–D2 are
wide/merge-lane only).

## What D0–D2 built (the msh mechanism + the two overwrite-mode bindings)

The interior merge sponge (`m4interior::sponge_overwrite`) is **OVERWRITE-mode**:
the keccak preimage rate limbs ARE the absorbed message block (no XOR recovery).
So binding "absorbed block == pv(opvs)" is a direct pair-recompose:

```
recompose = pcol(lb) + pcol(lb+1)·2^16      (lb = 4·(j/2) + 2·(j%2), value j in 0..34)
msh[p]·sf(0)·(recompose·rr − pv(half + OPV_INNER + 34·block + j)) == 0
```

where `rr = monty_rr()` = R (pv rides the Monty transcript encoding, so pv = v·R;
the absorbed value is canonical v; recompose = v; recompose·R = pv). **NB the
factor is `c(rr.as_canonical_u32())`, the plain field R — NOT `cf(rr)`, which
re-encodes rr into its Monty WORD R² (this was a real bug caught in D1).**

The **msh ring** (D0) is a per-merge-perm one-hot (`msh + p` fires on merge perm
p's 24 rows) that carries the compile-time block index into `eval` (a `pv(i)`
index must be a compile-time constant; the merge perms sit at data-dependent
rows). POSITIVELY PINNED — the csel-vs-msh difference: one-hot `Σ==mreg` +
start-edge anchor + forward rotation (`mrot` materialized) + `when_last_row`
root-slot anchor, so a DROPPED ring is UNSAT, not a silent binding vanish.

Columns: **+54 wide-only** (msh = `merge_perms()` = 53, mrot = 1). Interior
gate_width grew by 54; narrow/leaf untouched.

Negatives:
- `interior_neg_msh_ring` (D0): drop entire ring / drop end-anchor / spurious
  one-hot bit / tamper mrot → all UNSAT.
- `interior_neg_merge_msg` (D1): tamper child-L / child-R inner PV in the public
  opvs (keccak trace untouched → only the D1 binding can catch it) → UNSAT.
- `interior_epoch_fee_boundary` (D2): the documented-SAT boundary INVERTED to a
  UNSAT negative (consistent feeL+Σfee tamper now fails).

Measurements (Apple M5 Max / 36 GiB, AC, `/usr/bin/time -l`):
- Interior b2/q80/g22 peak footprint: **19.72 GB** (clean, block I/O 0) /
  20.64 GB (a run under external swap pressure); proof 1.54 MB. Baseline (PR #25):
  20.53 GB / 1.51 MB → within band, ≪ the ~22 GB stop-line. +0.03 MB proof.
- Leaf b4/q40/g22: **788.2 KB / 785 ms / 11.9 GB** — byte-identical to PR #29.

> **⚠️ These figures are pre-B″ and are NOT the baseline to difference against (noted 2026-07-27).** They were taken at **q40 leaf / q80 interior**; B″ ([#47](https://github.com/lai3d/qumbra-lab/issues/47)) moved the lanes to **q43 / q86** and nothing here was re-measured. Same-command baselines on `main` at the time of D3: **leaf 839.2 KB**, **interior proof 1.65 MB**. Subtracting today's numbers from the figures above yields **+51 KB that belongs to B″, not to whatever you are measuring** — D3 nearly wore that charge, and was spared only because its builder re-measured the baseline instead of trusting this file.
>
> **The general rule, which is why this note exists rather than a silent edit:** when a lane parameter moves, **every derived figure in every document becomes a trap for the next person who subtracts.** Re-measure the baseline with the same command on the same tree; never difference against a number whose lane you have not checked.

## D3 spec (the remaining leaf binding) — REMAINING

Goal: bind the M3 proof's inner PVs into the leaf gate's F0 challenger/sponge
INPUT, then expose the F0 output digest (`f0dig`) as a leaf public value (R2 from
issue #21 — non-hollow only after the input binding).

**Why D3 is harder than D1 (and was NOT rushed):**
1. **F0 is XOR-mode** (standard keccak challenger), not overwrite. On F0 blocks
   >0 the absorbed message word = `preimage_rate XOR prev_perm_output`. p3-keccak
   exposes `preimage` (already-XORed input), NOT the raw message — so recovering
   the message needs a per-bit XOR against the previous perm's output (bit-level
   state columns). The existing OREG/pbit/obit "XOR register file" (layout
   OREG..FSBITS) is the likely vehicle; confirm it exposes both operands' bits.
2. **Selector:** unlike the merge, F0 blocks sit at FIXED rows → reuse the
   existing flush-automaton one-hot `shsel` (`Shape::Obs{flush:0, block}`), NO
   new ring needed. The dead `shape_mosaic`/`WordBind` spec (m4gate.rs 577–738)
   already enumerates exactly which F0 word each inner PV should equal
   (`Pv(OPV_PVS+i)`, block slice `padded[block*34..]`) — resurrect it to drive
   the per-word `assert_eq(recovered_word, pv(OPV_PVS+i))`.
3. **f0dig:** mirror `f2dig` (decl ~layout 1144; fill ~5142; eval latch ~2720 on
   flush-0's last block via `shsel_index(...,0, flush_blocks[0]-1)`); expose as
   new PVs, bump `num_public_values`.
4. **Public-surface cascade (state before/after plainly):** exposing f0dig grows
   the leaf's `N_OPVS` → since `wide.tw = GATE_WIDTH` and the interior's `n_pvs`
   = the leaf's opvs, the interior inner-PV count, merge_perms(), msh width, and
   opvs layout ALL shift. This is the ONLY place the narrow-byte-identical
   invariant must break; disclose exact before/after N_OPVS / N_PVS / leaf size.

Acceptance: the PR #29 leaf SAT-MISS probes (`tamper_coverage`: opvs[OPV_PVS],
opvs[OPV_PVS+40], m4gate.rs ~6565) flip from SAT to UNSAT; circuit-exposed f0dig
== natively recomputed digest of the ordered PV list; deg ≤ 3; full suite green;
re-measure leaf size (WILL change — the public surface grew).

## Traps
- deg ≤ 3 is the hard bar (`constraint_degree_within_budget`), not the doc's "deg 5".
- The Monty factor: `c(rr.as_canonical_u32())`, never `cf(rr)`.
- Off-region rows must have new columns zeroed (fill) or `assert_bool`/one-hot fail.
- (D3 addition) The Monty factor is a MERGE-lane fact, not a universal one. The
  merge sponge hashes canonical u32s, so D1/D2 multiply by `rr`; the challenger
  absorbs `to_unique_u32()`, i.e. the Monty word itself, and `outer_pvs` already
  stores the inner PVs that way — so the F0 binding compares to `pv(i)` with NO
  factor. Applying D1's habit here would have made every honest trace UNSAT.
- (D3 addition) Appending to the outer public values is not free: the 棒 3-3
  Σfee rider reads the opvs TAIL, and `m4interior`'s const-assert only glues
  `EPOCH_FEE_LIMBS` to the M3 PV layout — it cannot see the tail. An append
  would have moved the rider's summands onto other data with every test green.
  There is now a value-level assertion on the tail.
