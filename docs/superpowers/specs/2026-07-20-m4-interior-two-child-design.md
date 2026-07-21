# M4 step 1 stage 2, 棒 2 + 棒 3 — interior verifier (two children + merge) design

> Design spec for the interior aggregation node: verify TWO child leaf proofs in
> one rectangle and merge their public digests into the interior root. Approved
> by the coordinator 2026-07-20 (all three hard requirements landed:
> aggregation-rung1 §7.4 EN+ZH dated implementation correction + issue #20
> annotation, `df53618`). Terminal state of brainstorming → next is writing-plans.

## Goal

Extend the `m4gate` single-child verifier (棒 1, DONE: SAT `7aca4df` + soundness
negatives `cc26b1d`) to the interior node: `build_interior_trace(&schedL,
&schedR, &opvsL, &opvsR)` producing a **2^19 rectangle** that in-circuit verifies
two wide leaf proofs and binds a keccak merge of their covered-tx digests as the
interior's outer public value. Correctness via `check_constraints` (棒 2/3);
peak-RSS vs the ≤ 32 GB / ≤ 30 s envelope is stage 3.

## Architecture: row-stacking (2^19 × 3626), NOT parallel columns

The interior runs the leaf-verification program **twice in the row dimension**:
child L in rows `0..24·nL`, child R in rows `24·nL..24·(nL+nR)`, then pad to 2^19.
One keccak lane processes all ~15,006 perms; the gate columns are reused across
both children.

**Why row-stacking and not parallel columns** (both have identical cell count /
RAM; parallel columns would even be *easier* — two `LaneBuilder` blocks both
anchored at row 0, no boundary re-anchor): the interior proof must have the SAME
committed width as a leaf proof (≈ 3626) so the grandparent verifies the same
shape and the aggregation tree **converges** to m4census's per-node fixed point.
Parallel columns double the width every level (3626 → 7252 → 14504 …) →
divergence → the aggregation premise breaks. Row-stacking keeps width ~constant
(fixed from level 1 onward, converges), so the child-boundary re-anchor is
unavoidable and correct.

## Verified height/width accounting (the §7.4 / issue #20 bank concern)

**Height is lane-perm-driven: 2^19.** The reduced-opening arithmetic (two children
× 290,400 value-terms = 580,800) does NOT consume ext-mul bank rows — it is
accumulated by the in-**lane** `PZACC` running sum, a direct deg-3 transition
constraint `pzacc += consz·(preg·v) + cx0·preg·w0c + cx1·prega·w1c`
(`m4gate.rs:3120–3123`), hosted on the query-program leaf-sponge absorb rows
(~2 words/row) which are already counted in the ~15,006 lane perms. The ext-mul
bank (`MUL_OFF`, 12 cols, one mul/row, micro-selector-gated) does only the sparse
chained fold arithmetic (M_X1 / M_FIN / INVZ / BREG / M_FHI / M_RO), co-located on
query perms — it is NOT a height driver.

Evidence (independently confirmed by the coordinator):
1. Code: the PZACC recurrence is a lane transition constraint, not a bank op.
2. 棒 1's single wide child SAT at **2^18 = 262,144 rows** while its reduced
   opening is 290,400 values — impossible under "1 value = 1 bank row"
   (290,400 > 262,144); hence lane-hosted (≈145k rows at 2 words/row < 180k lane
   rows). The design-doc's bank-based accounting was the false premise (issue #20
   annotated; §7.4 corrected, `df53618`).

Two-child driver: 15,006 perms × 24 = 360,144 min rows → **2^19** padded.
Reduced-opening ~290,400 absorb rows ⊂ those lane rows. **Single-lane ext-mul
bank fits; no 2-way parallelism.**

**Width** = 3626 (gate + keccak lane) **+ merge columns** (棒 3) **+ csel
degree-reduction materialized columns** (below). No bank-parallelism increment.

## Components

### C1 — `emit_child` extraction (approved fork; slice 2a)

Lift `build_gate_trace`'s ~580-line per-perm assembly body (`m4gate.rs:4109→4687`)
into `emit_child(values, row_offset, sched, opvs, &consts, &program, &layout,
shape, &mut child_meta)`. Then:
- `build_gate_trace` = `setup + emit_child(0, sched) + pad + fill_derived`
  — regression-guarded byte-identical by the existing 39 m4gate tests.
- `build_interior_trace` = `setup2 + emit_child(0, L) + emit_child(24·nL, R) +
  merge + pad(2^19) + fill_derived`.

Pure refactor, its own commit (the single-child path is frozen after 棒 1, so no
drift risk).

### C2 — child-boundary re-anchor in `eval` (slice 2b; the hard new work)

A `csel` boolean column = 1 on each child's first perm-row (row 0 and row 24·nL),
0 elsewhere. Every `when_first_row()` anchor becomes `csel`-gated (fires at both
child starts); every cross-perm `when_transition()` carry (phase automaton, flush
ring, challenge regs, RUNEV / PZACC / PREG, program ring) is **suppressed** where
`csel_next = 1`, so child L's end-state never bleeds into child R — child R
re-anchors instead. Shape-conditional: single-child / narrow has `csel ≡
is_first_row` → **byte-identical**.

**csel is constraint-pinned, NOT a free witness** (soundness): its value is forced
by constraints to equal the fixed child-boundary schedule — derived from the
existing program-ring re-pin + row-counter-reset signals that already
deterministically mark a child's first perm — so a malicious prover cannot place
`csel = 1` mid-child to re-anchor and bypass verification. Matching negative:
`csel` single-cell tamper (set an extra 1 / drop the boundary 1) → UNSAT.

**Degree budget** (permanent `assert(max_degree ≤ 3)` stays green): `when_transition
× (1 − csel_next)` bumps each affected deg-3 carry to deg-4 → materialize a
`(1 − csel_next)`-pre-multiplied product column per affected carry (the
flush-automaton precedent), keeping constraints deg ≤ 3. These columns are counted
in the width budget.

### C3 — two opvs sets (slice 2c)

Each child's cap comparison binds to its OWN outer public values. `build_interior_trace`
takes `opvsL / opvsR`; `emit_child` uses the child's opvs for the bind-bank cap
comparison (existing cap-comparison localized per child, csel-gated). The
interior's outer PV set = the merge root digest (C4), not the raw child opvs.

### C4 — merge sponge → interior root (棒 3)

Per aggregation-rung1 §2: a keccak sponge (reusing the `LaneBuilder` lane) absorbs
`(child-L digest, child-R digest)` → one root digest, exposed as the interior
circuit's outer public value, so a mismatch with the block body is detectable
without a proof. A handful of perms (negligible vs 15k), placed after both
`emit_child` calls and before the pad.

## Children sourcing

- **SAT / RSS iteration** uses the SAME leaf proof for both children (same shape,
  same opvs, merge(d, d)) — halves the ~0.67 s leaf-prove and is sufficient for
  SAT, per-lane binding, and the peak-RSS gate.
- **HARD PR-GATE (coordinator, non-negotiable): distinct children before stage-2
  PR acceptance.** L == R can mask a symmetry / cross-wiring bug that would slip
  into stage 3; proving one extra leaf costs ~0.67 s. Either land distinct-child
  SAT + per-child negatives before the PR, or (fallback) write the explicit reason
  in the PR remainder. Not an optional refine.

## Testing (all `check_constraints`, ~8 GB @ 2^19, rig-runnable — no full prove)

- `interior_two_child_satisfies` — two real leaf proofs verified in one rectangle
  (棒 2). Run with same-leaf first, then **distinct children** (PR-gate).
- Per-child tamper negatives: tamper child-L opening → UNSAT; independently tamper
  child-R → UNSAT (proves both lanes bind, not just one).
- `csel` single-cell tamper → UNSAT (C2 soundness).
- `interior_merge_binds_root` (root == keccak-merge(dL, dR)) + `interior_neg_wrong_merge`
  (root ≠ merge → UNSAT) (棒 3).

## Sub-slicing (one commit per testable slice; narrow byte-identical throughout)

1. **2a** `emit_child` extraction; `build_gate_trace` calls it once; 39 tests green.
2. **2b** `csel` column + constraint-pin + degree-reduction materialized columns;
   single-child `csel ≡ first_row` (byte-identical); csel negative.
3. **2c** `build_interior_trace` + `two_child_schedule` (same-leaf first) +
   `interior_two_child_satisfies` + two opvs binding.
4. **2d** per-child tamper negatives (+ the csel negative if not already in 2b);
   then **distinct-children** SAT + per-child negatives (PR-gate).
5. **棒 3** merge sponge + `interior_merge_binds_root` + `interior_neg_wrong_merge`.
6. **stage 3** (separate) two-child `prove` peak-RSS vs 32 GB; reproduce twice.

## Stop-rule (stage 3, aggregation-rung1 §6/§7)

Interior ≤ ~30 s / ≤ 32 GB. Over by ≥ 2× → STOP: write measured numbers, do not
force, flag the design-doc re-open + fallback ladder (i) per-level config (try b2)
/ (ii) k-tx batching / (iii) explicit-trust Poseidon2-interior (labelled). Over by
< 2× → fallback (i)/(ii) tuning. Do NOT touch the design repo — hand numbers to the
coordinator.

## Files

- Modify `crates/qlab-bench/src/m4gate.rs`: `emit_child`, `csel` + eval re-anchor +
  degree-reduction, `build_interior_trace`, two-opvs binding, merge gadget, tests.
- Create `crates/qlab-bench/src/m4interior.rs`: `two_child_schedule` (same-leaf +
  distinct), `run_m4interior` bench mode (stage 3 RSS).
- Modify `crates/qlab-bench/src/main.rs`: `mod m4interior` + `"m4interior"` dispatch.
- Docs: `docs/m4interior-stage3-run{1,2}.md` (stage 3 measurement).
