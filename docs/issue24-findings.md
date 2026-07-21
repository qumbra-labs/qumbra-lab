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
- **D3 (leaf F0 digest input binding + f0dig) — REMAINING.** Spec below. This is
  a substantially larger, consensus-critical change (XOR-mode sponge recovery +
  a leaf public-surface cascade) — deliberately scoped as a follow-on rather than
  rushed at the tail of D0–D2 (the stage-2 plan's own guidance for the
  merge-binding soundness slice: "consensus-critical, deliberately NOT rushed").

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
