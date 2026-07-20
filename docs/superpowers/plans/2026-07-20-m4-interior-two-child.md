# M4 interior two-child + merge (棒 2 + 棒 3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Spec: `docs/superpowers/specs/2026-07-20-m4-interior-two-child-design.md`.

**Goal:** Verify TWO wide leaf proofs in one 2^19 rectangle and keccak-merge their public digests into the interior root, meeting `check_constraints` SAT + soundness negatives, so stage 3 can measure peak RSS vs the ≤ 32 GB gate.

**Architecture:** Row-stacking — the leaf-verification program runs twice in the row dimension (child L rows `0..24·nL`, child R rows `24·nL..`), one keccak lane over ~15,006 perms, gate columns reused, padded to 2^19. Width stays ~3626 (+ merge + degree-reduction columns) so the aggregation tree converges. A constraint-pinned `csel` column re-anchors the phase automaton / carries at the child boundary.

**Tech Stack:** Rust 2021, Plonky3 0.6.1 (pinned), KoalaBear field, `p3-keccak-air` via `m4skel::LaneBuilder`, `p3-uni-stark` prove / `p3-air::check_constraints`.

## Global Constraints

- One commit per testable slice (分棒是硬要求). No giant WIP commit.
- Narrow byte-identical on every commit: `cargo test --release -p qlab-bench m4gate` must stay **39 passed** (37 narrow + `interior_single_child_satisfies` + `interior_single_child_negatives`).
- Permanent `assert(max_degree ≤ 3)` (`constraint_degree_within_budget`) stays green.
- Height is lane-perm-driven **2^19**; reduced-opening is lane PZACC, NOT ext-mul-bank — single-lane 12-col bank, no 2-way parallelism.
- **distinct children = HARD PR-gate** (L==R can mask symmetry bugs). Same-leaf allowed only for fast SAT/RSS iteration; distinct-child SAT + per-child negatives land before the PR (or explicit reason in the PR remainder).
- Do NOT touch the design repo (`qumbra-design`). No PR to anything but `main`, and only after coordinator independent acceptance.
- Heavy runs use `... 2>&1 | tail -N` (cargo detaches to background otherwise); foreground bare run.
- Correctness via `check_constraints` on the raw trace (no LDE): ~8 GB @ 2^19, rig-runnable. Full `prove` is stage 3 only.

---

## File Structure

- **Modify** `crates/qlab-bench/src/m4gate.rs`: extract `emit_child`; add `csel` column + eval re-anchor + degree-reduction columns; add `build_interior_trace`; two-opvs binding; merge gadget; interior tests.
- **Create** `crates/qlab-bench/src/m4interior.rs`: `two_child_schedule` (same-leaf + distinct), `run_m4interior` bench mode (stage 3 RSS).
- **Modify** `crates/qlab-bench/src/main.rs`: `mod m4interior` (~line 24) + `"m4interior"` dispatch arm (after `"m4tree"`, ~line 926).
- **Docs**: `docs/m4interior-stage3-run{1,2}.md` (stage 3 measurement).

---

## Task 2a: Extract `emit_child` (pure refactor, byte-identical)

**Files:**
- Modify: `crates/qlab-bench/src/m4gate.rs` (`build_gate_trace` body ~4001–4715)
- Test: existing `crates/qlab-bench/src/m4gate.rs` test module (no new test — the 39-test suite IS the gate)

**Interfaces:**
- Produces: `fn emit_child(values: &mut [Val], row_offset: usize, sched: &Schedule, opvs: &[Val], consts: &GateConsts, program: &[u32], layout: &GateLayout, shape: &GateShape, meta: &mut GateMeta)` — fills the per-child perm rows starting at `row_offset` (row-relative meta bookkeeping: push `row_offset + base_row`), performs the child's global self-checks (`assert_eq!(regs.qsel, nq)` etc.) internally. `build_gate_trace` and `build_interior_trace` both consume it.

- [ ] **Step 1: Identify the extraction span.** The per-perm assembly body runs from `let mut regs = Regs::new(shape);` (~4100) through the pad loop's predecessor — i.e. the `for (pi, ...) in ... ` perm walk + the global self-checks (`4109`–`4710`). The keccak-lane copy, `outer_pvs`, `lane_plan`, `hosted`/`chal_expect`/`fpoly`/`zvals`/`dcap` setup stay in the caller. `fill_derived` stays in the caller.

- [ ] **Step 2: Move the perm-walk + self-checks into `emit_child`.** Signature above. The walk currently indexes `values[row * gate_width + ...]` with `row = base_row + r`; change to `row = row_offset + base_row + r`. `meta.query_rows.push(base_row)` → `push(row_offset + base_row)`; `meta.field_draws.push((row, ...))` already uses `row`. Pad loop stays in caller (it pads `24*n_perms..rows`, unchanged for single child).

- [ ] **Step 3: Rewrite `build_gate_trace` to call it.** After setup: `let mut meta = GateMeta{...};` then `emit_child(&mut values, 0, sched, &opvs, &consts, &program, &layout, shape, &mut meta);` then the existing pad loop + `fill_derived` + return. No behavior change (row_offset=0).

- [ ] **Step 4: `cargo check`.** Run: `cargo check -p qlab-bench 2>&1 | tail -3`. Expected: `Finished`.

- [ ] **Step 5: Run the full suite (byte-identical gate).** Run: `cargo test --release -p qlab-bench m4gate 2>&1 | tail -6`. Expected: `test result: ok. 39 passed`.

- [ ] **Step 6: Commit.**
```bash
git add crates/qlab-bench/src/m4gate.rs
git commit -m "refactor(m4gate): extract emit_child(row_offset) from build_gate_trace; narrow byte-identical"
```

---

## Task 2b: `csel` child-boundary re-anchor (constraint-pinned) + degree reduction

**Files:**
- Modify: `crates/qlab-bench/src/m4gate.rs` (`GateShape`/`GateLayout` for the `csel` column + degree-reduction columns; `eval` anchor/carry gating; `write_row`/`fill_derived` fill; a wide `csel` negative)

**Interfaces:**
- Produces: `layout.csel: usize` (1 boolean column) + `layout.<carry>_dr: usize` degree-reduction columns (one per csel-gated carry family). `csel[row]` is constraint-pinned to the child-boundary schedule.

- [ ] **Step 1: Add the `csel` column to the layout.** In `GateLayout::from_shape` append `csel` (and the degree-reduction columns) after the current last gate column (`fpi`/`consz7` region — append at the end so narrow offsets before it are unchanged). Update `gate_width`. Add field(s) to the struct + the debug name table (`(CSEL, "CSEL")`). For narrow, these columns exist but are inert (csel ≡ first row).

- [ ] **Step 2: Write the failing csel-pin negative FIRST (TDD).** Add to the test module — this test can't pass until Step 4/5 pin csel:
```rust
#[test]
fn gate_neg_csel_narrow() {
    // On the single-child (narrow) trace, csel must equal is-first-row:
    // setting csel=1 on any interior row must be UNSAT (no mid-trace re-anchor).
    let w = GATE_WIDTH;
    assert_unsat(move |t, _o, qr, _fd| {
        let l = GateLayout::from_shape(&GateShape::narrow());
        // qr[0] is a query row well inside the trace (not row 0).
        t.values[qr[0] * w + l.csel] += Val::ONE;
    });
}
```

- [ ] **Step 3: Run it, expect FAIL** (csel not yet constrained → tamper is SAT). Run: `cargo test --release -p qlab-bench gate_neg_csel_narrow 2>&1 | tail -4`. Expected: FAIL ("expected UNSAT but constraints were satisfied").

- [ ] **Step 4: Pin `csel` by constraint (soundness core).** In `eval`: `csel` is boolean; `csel == 1` exactly on a child's first perm-row. Derive it from the existing child-start signal — the same condition `build_gate_trace`'s reset uses (`next` query slot role `R_ABS_F34/F16` at the leaf-start, or equivalently row 0 ∨ the interior child-boundary row). Concretely: `assert_bool(csel)`; `when_first_row().assert_one(csel)`; and a transition constraint tying `csel_next` to the child-boundary indicator (the program-ring re-pin / row-counter-zero signal already present) so it is 0 everywhere except a genuine child start. For narrow (single child) this forces `csel ≡ is_first_row`. Fill side: `write_row` sets `csel = (row == 0 || row == child_r_offset)`; `build_interior_trace` passes the offset (Task 2c), `build_gate_trace` passes `None`.

- [ ] **Step 5: Gate the anchors + suppress boundary carries.** Convert `when_first_row()` anchors that must re-fire per child to `csel`-gated `assert_zero(csel * (X - init))`; gate the cross-perm `when_transition()` carries (phase automaton `phc/phq/phd`, flush ring `fring`, `chal`, `RUNEV/PZACC/PREG`, program ring `pr`) with `(1 - csel_next)` so state does not bleed across the boundary. Enumerated anchor sites to review: the `when_first_row()` calls (grep `when_first_row` in `eval`) and the ring/carry `when_transition()` blocks (`pr` ring ~1824, `pzacc/preg` ~3116, `fring` rotation, `chal` assembly). Each converted carry that reaches deg 4 gets a materialized `(1-csel_next)`-product column (Step 6).

- [ ] **Step 6: Degree reduction.** For each carry bumped to deg 4 by the `(1-csel_next)` factor, add a materialized product column filled in `fill_derived` (mirror the existing flush-automaton degree-reduction pattern), so the constraint references the column (deg ≤ 3). Guard: `constraint_degree_within_budget` must stay green.

- [ ] **Step 7: Run the csel negative + degree guard + full suite.** Run: `cargo test --release -p qlab-bench m4gate 2>&1 | tail -8`. Expected: `40 passed` (39 + `gate_neg_csel_narrow`), including `constraint_degree_within_budget`.

- [ ] **Step 8: Commit.**
```bash
git add crates/qlab-bench/src/m4gate.rs
git commit -m "feat(m4gate): constraint-pinned csel child-boundary re-anchor + degree reduction; narrow byte-identical"
```

### 2b progress (2026-07-20)

- **2b-i DONE** (`1bd8a3f`): csel column + completion-gated soundness pin
  (`csel_next·(1-endg)==0`, option B) + `gate_neg_csel_narrow`. Findings:
  (a) the completion signal is **`endg`** (last-query r=23), NOT `qsel==nq` — the
  final qsel→nq rotation IS the suppressed boundary transition, so qsel is never
  nq at row R-1; verified vs `lane_plan` (queries are the last region per child).
  (b) csel grows the shared gate → leaf 3626→**3627** (odd) → `wide().tw` now
  **derives from `GATE_WIDTH`** (so future gate-column adds auto-track); the odd-`f`
  trace-last path is exercised and SATs (1b-A generalization holds);
  `flush_bytes[2]` 116192→116224.
- **2b-ii DONE** (`4eb4a81`): 27 per-transcript first-row anchors csel-gated
  (`when_first_row().assert(col,v)` → `assert_zero(csel·(col-v))`), incl. **`blkcnt`**
  (flush-automaton block counter — a subagent flag caught it; it was missing from
  the initial enumeration). Left the csel self-anchor + `when_last_row` as-is.
  Degree-neutral; narrow verdicts unchanged; 40 green.
- **2c scaffolding DONE** (`7c38898`): `child_derived` + `build_interior_trace`
  (row-stacked, 2^19, single opvs same-leaf) + `m4interior::two_child_schedule` +
  `mod m4interior`. Two-child `check_constraints` BUILDS and passes rows
  0..200614 (both children's obs+dup phases + ring-based re-anchor). **nl = 8359
  lane perms** (898 obs + 5 refill + 1 trailer + 855 dup + 6600 query) → child R
  starts at row 200616. `interior_two_child_satisfies` `#[ignore]`'d pending
  2b-iii.
- **2b-iii PENDING (pinpointed) — the boundary carries at row 200615.** Two-child
  check_constraints fails at **row 200615 = child L's last row** with ~250 TRANS
  constraints: the active query-phase-end carries that would bleed child L's
  state into child R's csel-anchored first row (200616). Confirmed families (via
  `dump_constraint`): qsel ring rotation (#3673: qsel/qadv), XOR/OREG carry
  (#4450), plus pr ring, blkcnt, chal assembly, pzacc/preg, runev, and the
  sponge/path continuation carries. Fix: gate each with `(1 - csel_next)` in its
  `when_transition` block; deg-3 carries × (1-csel_next) → deg 4 → materialize a
  `(1-csel_next)`-product column. Gate: two-child check_constraints advances past
  200615 (peel further rows as needed) → SAT; narrow suite stays 40-green; degree
  ≤ 3.

  **REFINEMENT (2026-07-20, from reading the carries): gate only the CONFLICTING
  carries — the failing set — not all anchored-state carries.** A carry conflicts
  only if its boundary value ≠ the fresh anchor value:
  - `qsel` rotation (#3673) CONFLICTS: at child L's last r=23 it rotates the
    one-hot to slot `nq` (done), but child R anchors slot 0 → gate it. Deg 2
    (gate = materialized `qadv`) → gated deg 3, NO materialization.
  - `qcnt` decrement (~1966) does NOT conflict: at the boundary `dec=sf23*phq=1`,
    `qcw=1` reloads it to `qslots` = the fresh anchor value → agrees. SKIP (and
    skipping avoids its deg-3→4 materialization, gate `sf23*phq` is deg 2).
  - `pr` ring does NOT conflict: cycles mod `qslots` back to `program[0]` (fresh)
    after the last query. SKIP.
  Fresh-pass method: gate `qsel`, run the heavy two-child SAT once, read the
  STILL-failing indices at 200615, `dump_constraint` each for family+degree, gate
  deg-2 ones inline + materialize only deg-3 ones, repeat until 200615 clears.
  Confirmed failing families to triage: qsel, oreg (#4450 deg 3 → materialize),
  clusters #4361/#4398/#4714/#4766+/#4906/#4966+/#5164+/#5405+/#5498+. Materialized
  columns grow GATE_WIDTH → update `gate_shape_wide_values` flush_bytes[2] +
  `gate_layout_narrow_reproduces_consts`. (Subagent dispatch was 529-blocked
  2026-07-20; do inline or retry when API stable. Tree clean at the 2c-scaffold
  commit `7c38898`.)

  **TWO-PRONGED FIX (2026-07-20, from classifying every failing cluster at row
  200615 via dump_constraint) — this makes 2b-iii tractable.** The ~250 failing
  constraints split into two categories, NOT one uniform "gate everything":
  - **Anchored families → GATE with `(1-csel_next)`** (they re-anchor fresh at
    child R, so their carry must be suppressed): `qsel` rotation (#3673, DONE
    `f63c92a`), `fring` rotation (#4361, deg-3 → materialize 8), `grp` rotation
    (#4714, deg-2), `curch` assembly (#4766, deg-3), `chal` assembly, `blkcnt`
    (deg-3), `preg`/`pzacc`, and the phase carries `phc`/`phd`/`phq` (deg ≤2).
    Skip the AGREEING ones (`qcnt`→qslots, `pr`→program[0], `bidx`→slot0).
  - **Non-anchored fold/arith registers → FILL-CONTINUITY (no gating, no columns).**
    Clusters #4450 (`oreg`), #4906–#5405 (`xreg`/`xfin`/`runev`/`breg`/`inv2s`/
    `invz`/`mchain` + msel), #5498 (`scr`/`f2dig`), and `fpreg`, `a0/a1/a2`,
    `p0/p1`, `px0`, `fa2`, `zn`. These are freeze-carried (continuity constraint
    `nv==cv` when their update gate is off); child R's fresh `Regs::new` (0)
    breaks the freeze → conflict. They are NOT anchored and are harmless (child
    R's queries overwrite them before use), so the cheap fix is to make child R
    INHERIT child L's final values instead of resetting to 0 — the freeze then
    holds. Implementation: `emit_child(L)` already returns its final `Regs`;
    give `emit_child` an optional `inherit: Option<&Regs>` and, for child R, copy
    the non-anchored fields from child L's final regs (keep the anchored fields
    fresh — they are re-anchored by csel + gated carries). This AVOIDS the
    infeasible per-constraint deg-3 materialization for the big loop families
    (oreg=68, fold regs).
  Order for the next pass: (1) implement fill-continuity for child R (clears the
  fold/oreg/scr clusters); (2) gate the remaining anchored families (materialize
  only fring/blkcnt/curch deg-3 ones — small); (3) run two-child SAT → clears
  200615; (4) un-ignore `interior_two_child_satisfies`. Keep narrow 40-green +
  degree ≤3 throughout; materialized columns update flush_bytes[2] + the layout
  reproduce-consts test.

  **2b-iii + 2c DONE (2026-07-20, `f63c92a`→`a37d6be`). TWO-CHILD SAT.** The
  boundary carries were resolved exactly per the two-pronged plan, and the full
  2^19 two-child rectangle is `check_constraints`-SAT (`interior_two_child_satisfies`
  un-ignored, passes). Peel history: 250 → (qsel gate) → (fill-continuity for
  oreg/fold-arith) 73 → (chal/idxr/curch inherit + grp/coef gate) 4 → (phc/phd/phq
  gate) 3 → (fring/blkcnt gate via materialized frgm/bcbd) 0. Degree ≤3 held
  (frgm=sf(23)·b0next deg2, bcbd=blkcnt-delta deg3, filled next-row in
  fill_derived). GATE_WIDTH 3626→3629; flush_blocks[2] 855→856. m4gate suite 41
  passed, all narrow byte-identical. **NEXT: 2d (distinct children + per-lane
  negatives, PR-gate) → 棒 3 (merge) → stage 3 (RSS).**

  **2d DONE (2026-07-20, `df02253`→`3fffb74`, 4 clean commits). DISTINCT
  TWO-CHILD SAT + per-lane negatives (the L≠R HARD PR-gate).** Full m4gate suite
  **43 passed / 0 failed** (136 s), all 37 narrow byte-identical, degree ≤3 for
  BOTH narrow and interior. Slices:
  - **2d-1** (`df02253`): `m4gaterec::{bucket_instance_seeded,consensus_proof_seeded}`
    + `m4treerec::leaf_proof_variant` (seed `0x1234…def0`, same 2-in/2-out balanced
    shape → distinct caps + inner PVs); `two_child_schedule(true)` wired; test
    `variant_child_has_distinct_opvs` (opvs_l ≠ opvs_r).
  - **2d-2** (`6642ac1`): **per-child opvs routing.** Interior public values =
    `outer_pvs(L) ++ outer_pvs(R)`; each child's cap comparison selects its OWN
    half. New cols `chi` (running child selector: 0=L, 1=R; pinned bool /
    chi[0]=0 / transition `chi_next = chi + csel_next` → rises exactly at the
    soundness-pinned csel boundary → fully determined) + `cc[cap_len]` =
    materialized `chi·caps8` so the mux `pvL + chi·(pvR−pvL)` stays **deg 3**.
    `VerifierGateAir.n_children` (num_public_values = n_opvs·n_children);
    `new_interior()` = wide + 2 + routing on. `build_interior_trace` emits doubled
    opvs + fills chi; `opvs_l==opvs_r` guard removed. **Routing is gated on
    n_children>1 — narrow AND single-wide keep the exact pre-2d constraint
    (route=false), so byte-identical; only the layout widened: GATE_WIDTH 3629→
    3638, wide leaf tw→3638 → F2 116576 B / 858 blocks (pinned tests updated).**
    Degree guard extended to cover `new_interior()`.
    ⚠ **KEY FINDING for 棒 3 / future:** in `eval`, `pv()` public values are
    consumed at EXACTLY ONE site — the cap comparison (m4gate.rs ~line 2129,
    `cap_limb_opv`, caps region only). The inner-PV half of opvs (indices ≥
    n_caps·cap_len·16) is NOT read by any constraint (it rides the FS transcript
    via trace bytes, which is already per-child/trace-local). So "per-child opvs
    routing" = routing the caps comparison only; there is no separate F0-PV
    absorb constraint to route. 棒 3's merge should digest each child's opvs
    (`aggregation-rung1 §2`) and expose the root — the child caps are already
    bound per-child by 2d-2.
  - **2d-3** (`e36858d`): `interior_two_child_satisfies_distinct` — DISTINCT L≠R,
    `check_constraints`-SAT under `new_interior` (30 s @ 2^19). `wide_shared_distinct()`
    caches the pair (both ~12 GB proves once, shared with 2d-4).
  - **2d-4** (`3fffb74`): `interior_two_child_negatives` — one distinct trace,
    clone-per-probe, all UNSAT: (a) child-L opening (fails row ~42k, lower), (b)
    child-R opening independently (fails row ~243k, upper — BOTH lanes bound), (c)
    child-R opvs 2nd half (fails cap-comparison #4076 in child-R region — routing
    binds R to its own half). `query_rows` splits nq|nq. `is_unsat_interior` helper.

  **NEXT: 棒 3 (Task 3 — merge sponge → interior root) → stage 3 (Task S3 — RSS
  vs 32 GB).** 棒 3-1 (native merge + exposed root) is DONE (`560377d`); the
  remaining 棒 3-2 (eval binding of the merge preimages to `pv(opvs)` + squeeze to
  `pv(root)` + wrong-merge negative) is the real soundness slice — see the "棒 3
  progress" block under Task 3 for the precise blueprint (the `pv`-index-must-be-
  constant finding → per-block `msh` selector columns). Range stays locked out of
  stage 3's measurement until 棒 3-2 lands (coordinator's guard).

  Earlier general note:
  suppression `(1-csel_next)·carry` only *matters* where csel_next=1 (two children
  only), so it is untestable standalone. Plan: build 2c's `build_interior_trace`
  first; the two-child `check_constraints` will fail at exactly the carries that
  conflict with the re-anchor (peel-the-onion) — suppress + degree-reduce each as
  a sub-commit, tested immediately. Carries to expect: program ring rotation,
  qcnt/qsel rotation, blkcnt reload/decrement, fring rotation, grp/coef rotation,
  chal assembly, pzacc/preg, fpreg, runev, and the sponge/path continuation
  carries. Each deg-3 carry × (1-csel_next) → deg 4 → materialize a
  `(1-csel_next)`-product column (flush-automaton precedent), counted in width.

---

## Task 2c: `build_interior_trace` + `two_child_schedule` + SAT

**Files:**
- Modify: `crates/qlab-bench/src/m4gate.rs` (`build_interior_trace`)
- Create: `crates/qlab-bench/src/m4interior.rs` (`two_child_schedule`)
- Modify: `crates/qlab-bench/src/main.rs` (`mod m4interior`)

**Interfaces:**
- Consumes: `emit_child` (2a), `csel` fill (2b), `m4treerec::{leaf_proof, walk_leaf}`.
- Produces: `pub(crate) fn build_interior_trace(schedL: &Schedule, schedR: &Schedule, opvsL: &[Val], opvsR: &[Val], shape: &GateShape, extra: usize) -> (RowMajorMatrix<Val>, GateMeta)` — 2^19 rectangle, both children row-stacked, per-child opvs. `m4interior::two_child_schedule(distinct: bool) -> (Schedule, Schedule, Vec<Val>, Vec<Val>)`.

- [ ] **Step 1: `two_child_schedule` (same-leaf first).** In `m4interior.rs`:
```rust
pub(crate) fn two_child_schedule(distinct: bool) -> (Schedule, Schedule, Vec<Val>, Vec<Val>) {
    let (leaf_l, opvs_l) = crate::m4treerec::leaf_proof();
    let sched_l = crate::m4treerec::walk_leaf(&leaf_l, &opvs_l);
    if !distinct {
        return (sched_l.clone(), sched_l, opvs_l.clone(), opvs_l);
    }
    let (leaf_r, opvs_r) = crate::m4treerec::leaf_proof_variant(); // distinct M3 input
    let sched_r = crate::m4treerec::walk_leaf(&leaf_r, &opvs_r);
    (sched_l, sched_r, opvs_l, opvs_r)
}
```
(For same-leaf, `leaf_proof_variant` is unused; add it in Task 2d for the PR-gate.)

- [ ] **Step 2: `build_interior_trace`.** Assemble: setup for both children (concatenate lane inputs L then R for one `p3_keccak_air` lane; height = `((nL+nR)*24).next_power_of_two()` = 2^19); `emit_child(&mut v, 0, L, opvsL, ...)`; `emit_child(&mut v, 24*nL, R, opvsR, ...)`; per-child `csel` at rows 0 and `24*nL`; pad; `fill_derived`. Merge gadget deferred to 棒 3 (Task 3). `meta.opvs` = `[opvsL ++ opvsR]` for now (merge root in Task 3).

- [ ] **Step 3: Write the failing SAT test.**
```rust
#[test]
fn interior_two_child_satisfies() {
    let _g = heavy_lock();
    let (sl, sr, ol, or) = crate::m4interior::two_child_schedule(false);
    let (trace, meta) = build_interior_trace(&sl, &sr, &ol, &or, &GateShape::wide(), 0);
    check_constraints(&VerifierGateAir::new_with_shape(GateShape::wide()), &trace, &meta.opvs);
}
```

- [ ] **Step 4: Run, expect FAIL, then implement until SAT** (peel-the-onion analogue: use `WIDE=1 CIDX=<n> cargo test dump_constraint` to diagnose any failing constraint; the likely surfaces are the csel boundary at row `24*nL` and the per-child opvs cap comparison). Run: `cargo test --release -p qlab-bench interior_two_child_satisfies -- --ignored --nocapture 2>&1 | tail -20`.

- [ ] **Step 5: Wire `mod m4interior` in `main.rs`** (declaration only this task; dispatch arm in stage 3). Run: `cargo check -p qlab-bench 2>&1 | tail -3`.

- [ ] **Step 6: Full suite green.** Run: `cargo test --release -p qlab-bench m4gate 2>&1 | tail -6`. Expected: prior tests still pass + `interior_two_child_satisfies` ok.

- [ ] **Step 7: Commit.**
```bash
git add crates/qlab-bench/src/m4gate.rs crates/qlab-bench/src/m4interior.rs crates/qlab-bench/src/main.rs
git commit -m "feat(m4interior): build_interior_trace two children row-stacked (2^19 SAT, same-leaf)"
```

---

## Task 2d: per-child negatives + distinct children (PR-gate)

**Files:**
- Modify: `crates/qlab-bench/src/m4gate.rs` (interior negatives), `crates/qlab-bench/src/m4treerec.rs` (`leaf_proof_variant`)

**Interfaces:**
- Consumes: `build_interior_trace`, `is_unsat_wide`, `wide_shared`-style caching.
- Produces: `m4treerec::leaf_proof_variant() -> (Proof<Config>, Vec<Val>)` (a leaf proof of a DISTINCT M3 input, so the two children differ).

- [x] **Step 1: `leaf_proof_variant` (distinct child).** In `m4treerec.rs`, mirror `leaf_proof` but drive `consensus_proof` with a distinct instance (e.g. a second `BucketInstance` seed) so `opvs` differ. Verify `opvs_l != opvs_r`.

- [x] **Step 2: Failing per-child + distinct negatives (TDD).** Add `interior_two_child_negatives` mirroring `interior_single_child_negatives`: build one interior trace (distinct children), clone-per-probe, assert UNSAT for: tamper child-L opening (`qrL[0]` region); independently tamper child-R opening (`qrR[0]` region, i.e. rows ≥ `24*nL`); tamper child-R opvs cap. Each proves the lane it targets is bound.
```rust
#[test]
fn interior_two_child_negatives() {
    let _g = heavy_lock();
    let (sl, sr, ol, or) = crate::m4interior::two_child_schedule(true); // DISTINCT
    let l = GateLayout::from_shape(&GateShape::wide());
    let w = l.gate_width;
    let (base, meta) = build_interior_trace(&sl, &sr, &ol, &or, &GateShape::wide(), 0);
    // meta must expose per-child query rows; split by row_offset (< or ≥ 24*nL).
    // probe(child-L opening), probe(child-R opening), probe(child-R opvs) -> all UNSAT
    // (use is_unsat_wide, clone-per-probe as in interior_single_child_negatives)
}
```

- [x] **Step 3: Run, expect FAIL then implement** (extend `GateMeta` if needed so per-child query rows are distinguishable, e.g. `query_rows` already carries absolute rows — child R's are ≥ `24*nL`). Run: `cargo test --release -p qlab-bench interior_two_child_negatives -- --nocapture 2>&1 | tail -15`. Expected: all probes UNSAT → test ok.

- [x] **Step 4: distinct-child SAT (PR-gate).** Also assert `interior_two_child_satisfies` passes with `two_child_schedule(true)` (add a `_distinct` variant test or parametrize). Expected: SAT with distinct children.

- [x] **Step 5: Full suite green.** Run: `cargo test --release -p qlab-bench m4gate 2>&1 | tail -8`.

- [x] **Step 6: Commit.**
```bash
git add crates/qlab-bench/src/m4gate.rs crates/qlab-bench/src/m4treerec.rs
git commit -m "feat(m4interior): per-child + distinct-children negatives (PR-gate: L!=R)"
```

---

## Task 3 (棒 3): merge sponge → interior root

**Files:**
- Modify: `crates/qlab-bench/src/m4gate.rs` (merge gadget in `build_interior_trace` + eval), `crates/qlab-bench/src/m4interior.rs`

**Interfaces:**
- Consumes: `LaneBuilder` keccak lane, both children's public digests (`d_i` from each child's opvs / public commitment).
- Produces: interior outer PV = `keccak-merge(dL, dR)`; `build_interior_trace` `meta.opvs` = the root digest.

- [x] **Step 1: Compute the merge in the builder.** After both `emit_child` calls, append a keccak sponge perm (or few) absorbing `(dL, dR)` → root digest; store as `meta.opvs`. `dL/dR` = each child's covered-tx digest (define as the keccak of the child's opvs, matching aggregation-rung1 §2).

### 棒 3 progress (2026-07-20)

**棒 3-1 DONE (`560377d`). Native merge + exposed root (UNBOUND).** `m4interior`:
overwrite-mode `sponge_overwrite` (leaf-sponge convention: rate overwritten,
capacity carried, pad10*1) + `merge_root(opvsL, opvsR)` / `merge_perm_inputs` /
`MERGE_ROOT_LIMBS=16`. `root = keccak(keccak(opvsL) ‖ keccak(opvsR))`; `dL/dR`
serialize each child's full opvs as **u32-LE per value** (KoalaBear < p < 2^31 →
lossless) — commits caps + covered-tx inner PVs (⊇ §2's covered digests).
`build_interior_trace` appends the merge perms to the keccak lane (**height stays
2^19**: nm ≈ 89 perms — child-L sponge 44 blocks + child-R 44 + root 1, each opvs
= 1492 vals × 4 B = 5968 B → 44 blocks — fit the pad headroom), sets
`meta.opvs = opvsL ++ opvsR ++ root`; `new_interior` `num_public_values +=
MERGE_ROOT_LIMBS`. `interior_merge_native` asserts the root tail == native merge +
`check_constraints` SAT. **No new columns → narrow / single-wide byte-identical**
(merge is `build_interior_trace`-only; KeccakAir checks the merge keccak-f, but
the preimages are NOT yet bound to `pv` — soundness-vacuous until 棒 3-2). 6
interior tests green.

**⚠ 棒 3-2 (eval binding) — the real soundness work, DELIBERATELY NOT rushed at
session end (consensus-critical: aggregation-rung1 §3 — an interior merge-binding
bug = silent supply inflation for syncing nodes, detectable by no one).** Precise
blueprint + the hard constraint discovered:

- **THE KEY CONSTRAINT: `pv(i)` needs a compile-time-constant index `i`** — you
  CANNOT index public values by a trace value. But the merge perms sit at
  *data-dependent* rows (row `24·(nl+nr) + 24·b`, and `nl` is data-dependent). So
  the binding cannot be "on the row holding block b, bind pv(34·b+j)" via a row
  counter. **Solution (flush-automaton `shsel` pattern): a per-merge-block one-hot
  selector column `msh[b]` (b in 0..nm), builder-filled to fire on exactly merge
  perm b's row.** Then `eval` does `for b in 0..nm { emit block-b binding gated by
  msh[b], reading pv at the FIXED indices for block b }`. `nm` selector columns
  (~89 full-opvs) + `mreg`/`mcnt` (2, the pin below).
- **⭐ WIDTH FINDING (measured 2026-07-20): the msh/mreg/mcnt columns are
  WIDE-ONLY → NO narrow cascade, NO flush-geometry change, narrow trivially
  byte-identical.** `narrow.gate_width = 3638` but `wide.gate_width = 3788`
  ALREADY differ (dump_cols probe) — the aggregation tree converges only
  approximately (~+150 cols/level; the prototype is 2-level so it never
  compounds). `wide().tw = GATE_WIDTH = 3638` (the leaf width the interior
  *verifies*) is INDEPENDENT of `wide.gate_width` (the interior's own rectangle).
  So adding `~91` columns to the WIDE layout ONLY (via a shape flag / wide-only
  tail region) grows `wide.gate_width` (3788 → ~3879, +2.4% cells, marginal for
  the stage-3 RSS gate) while `narrow.gate_width`, `wide().tw`, and every wide
  flush pin stay put. Add via a `merge_lane: bool` on `GateShape` (narrow false /
  wide true) → `merge_perms()` returns 0 for narrow, `nm` for wide; layout tail
  `msh = cc + cap_len` with `msh_width = merge_perms()`, `gate_width = msh +
  msh_width + 2` (mreg, mcnt). narrow `msh_width=0` → `gate_width` unchanged.
- **⭐ POSITIVE PIN (the real soundness difficulty — msh must be FORCED to fire,
  unlike csel): merge-at-END + `mreg`/`mcnt`.** csel's absence self-destructs
  (automaton conflict → UNSAT); msh's absence would just make the binding vanish
  (root unconstrained). So msh needs POSITIVE enforcement. **Place the merge perms
  at the trace END** (restructure `build_interior_trace`: `all_inputs = childL ++
  childR ++ [zeros; R/24 − nl − nr − nm] ++ merge`, so the root perm's last row ==
  `last_row`; `nm`/`R` are shape constants so the merge-region start row `R−24·nm`
  is FIXED). Pin the region with a monotone boolean `mreg` (0→1 once) + a counter
  `mcnt` asserted `== 24·nm` at `last_row` → forces exactly the last `24·nm` rows
  to be the merge region. The `msh` one-hot ring lives inside `mreg` (anchored:
  `last_row` ⇒ slot `nm−1` = root perm; rotate per perm boundary `sf(23)`; zero
  outside `mreg`). A misplaced/absent msh then either breaks `mcnt==24nm` or
  collides with a child/pad perm's keccak → UNSAT. Verify with a **msh-tamper
  negative** (drop the boundary 1 / add a spurious 1 → UNSAT) — do NOT trust the
  reasoning, let the negative prove the pin.
- **Binding families (mirror the leaf-sponge overwrite absorb):**
  1. **Message → pv (rate).** For merge perm b (a child-L opvs block, b<44):
     preimage rate lane `l` (0..17), limbs `4l..4l+4` hold opvs values `2·(34b/2+…)`.
     Concretely value at block-position `j` (0..34): `lane=j/2`, `base=4·(j/2)+2·(j%2)`;
     constraint `pcol(base) + pcol(base+1)·2^16 == pv(off + 34·b + j)` (off=0 child
     L, `n_opvs` child R), gated `msh[b]`. **KeccakAir already range-bounds the u16
     preimage limbs**, so this deg-1-in-cols pair-recompose is sound. Deg 2 with the
     `msh[b]` gate. **Last block is padded**: positions past the real opvs bind to
     the FIXED pad constants (`^0x01 … ^0x80`), not pv.
  2. **Capacity chain.** perm p's preimage capacity (limbs 68..100) == perm (p−1)'s
     output capacity (`ocol` 68..100) — a perm-boundary transition
     `sf(23)·chain_sel·(nv(pcol(i)) − cv(ocol(i)))`, i in 68..100 (mirror the
     existing `R_ABS_C34` carry at m4gate.rs:2060). First block of each sponge
     (child-L b0, child-R b0, root): capacity == 0.
  3. **dL/dR → root perm.** root preimage limbs 0..16 == child-L-last-perm `ocol`
     0..16 (dL digest), 16..32 == child-R-last-perm `ocol` 0..16 (dR), 32.. = pad
     consts. Cross-perm (chain the two sponge digests into the root perm's message).
  4. **Squeeze → pv(root).** root perm output digest `ocol` 0..16 ==
     `pv(2·n_opvs + k)`, k in 0..16, gated on the root perm's selector.
- **Negatives:** `interior_neg_wrong_merge` (root tail tamper → UNSAT); a
  tamper-opvs-changes-root negative (flip an opvs entry that feeds the sponge →
  root mismatch → UNSAT — proves the message binding is live). Both under
  `new_interior`. Keep degree ≤ 3 (msh-gated deg-2 binds; the pair-recompose is
  linear) and the narrow suite byte-identical (msh columns inert for n_children=1).
- **Sub-slicing 棒 3-2 (each its own commit, TDD) — DECIDED: root-only + tree-merge:**
  - **3-2a — DONE (`126f258`).** merge-at-END restructure (childL | childR |
    zero-pad | merge, so the root perm's last row == `last_row`) + `mreg`/`mcnt`
    region pin (wide-only) + `interior_neg_merge_region` (drop mreg / bump mcnt /
    spurious early mreg → UNSAT). `GateShape::merge_lane` + `merge_perms()` (=
    `2·blocks(n_pvs·4) + 1` = 53 for wide — hashes each child's OWN opvs = the
    interior's inner PVs `n_pvs`=852, NOT the 1492 outer). narrow byte-identical
    (merge cols wide-only), deg ≤ 3, m4gate 45 green.
  - **3-2b — capacity chain (makes the merge perms a genuine sponge).** ⭐ ESSENTIAL:
    keccak-f is a PERMUTATION (invertible), so without the chain a prover inverts
    the root perm to hit `pv(root)` for free → the root binding is vacuous. The
    chain (input capacity limbs 68..100 == previous perm's output capacity) turns
    it into a sponge → hitting `pv(root)` needs a full preimage (preimage
    resistance) → rate == opvs. **tree-merge = 3 independent sub-sponges** (childL
    kL=26 perms, childR kR=26, root 1), each starting capacity 0 → need cap-RESET
    markers at the 3 sub-sponge-start perms (merge perms 0, kL, kL+kR). Pin via
    `mcnt` thresholds: sub-sponge starts at `mcnt ∈ {1, 24·kL+1, 24·(kL+kR)+1}`
    (perm row-0s) — equality-comparator columns (`eq/inv` pairs, the flush-automaton
    `cmpa/cmpai` precedent) → a `mrst` reset flag; chain constraint
    `mb·(1−nv(mrst))·(nv(pcol cap) − cv(ocol cap)) == 0` at perm boundaries
    (`mb = mreg·sf(23)`), reset `mrst·pcol(cap) == 0`. Test: positive SAT +
    capacity-tamper negative (perturb a merge perm's input capacity → UNSAT).
  - **3-2c — dL carry + dR adjacency + root bind.** root perm (merge perm kL+kR)
    absorbs `dL ‖ dR`: dR = childR's last perm output (kL+kR−1) is ADJACENT to the
    root perm → bind `root-preimage[16..32] == prev ocol[0..16]` via the r=23→r=0
    transition (no carry). dL = childL's last perm output (kL−1) is kR perms before
    root → a `dlr` carry register (16 limbs) captured at childL-end (mrst-for-childR
    row: prev-perm output) and freeze-held through childR to the root perm; bind
    `root-preimage[0..16] == dlr`. Root squeeze: `root ocol[0..16] == pv(2·n_opvs+k)`.
    Tests: `interior_merge_binds_root` (SAT) + `interior_neg_wrong_merge` (tamper
    root pv → UNSAT) + tamper-a-child-opvs-feeding-the-sponge → root mismatch → UNSAT.
  - Soundness note for coordinator review: root-only relies on keccak preimage
    resistance (standard for hash-based); the capacity chain + `root==pv(root)` +
    cap comparison (binds `pv(opvsL/R)` to children) close the loop WITHOUT the
    ~89-col per-block message binding.
- **Consideration for the implementer:** 棒 3-1 shipped **full-opvs** `merge_root`
  (89 blocks / 89 msh cols). A smaller commitment (e.g. inner-PVs only = the
  covered-tx digests, offset `n_caps·cap_len·16`, ~53 blocks) would cut msh
  columns and is arguably MORE §2-faithful ("covered digests" not caps) — but
  requires re-defining `merge_root` (and updating `interior_merge_native`, which
  pins the full-opvs value). Since msh is wide-only (no cascade / RSS impact is
  marginal), full-opvs is fine to keep; shrink only if the ring width is
  unwieldy.
- **Coordinator soundness backstop:** the plan already requires coordinator
  independent acceptance before merge — the merge-binding soundness (the
  consensus-critical part) gets that adversarial review there; land 3-2a/3-2b on
  the branch with positive + tamper negatives, do not self-certify soundness.

- **⭐⭐ SIMPLIFICATION (2026-07-20 analysis) — ROOT-BINDING-ONLY drops the ~89-col
  message binding.** The per-block `msh` message binding (`preimage == pv(opvs)`)
  gives *unconditional* (constraint-level) "sponge input == opvs". But merge
  soundness is already achievable *computationally* (keccak preimage resistance —
  the standard bar for a hash-based system) with FAR less machinery:
  1. **Capacity chain** — each merge perm's input capacity (`pcol` 68..100) ==
     the previous perm's output capacity (`ocol` 68..100), reset to 0 at each
     sponge start (child-L b0, child-R b0, root). This makes the merge perms a
     genuine iterated sponge rather than independent keccak-f blocks.
  2. **`dL/dR → root perm`** — root perm preimage 0..16 == child-L sponge's last
     `ocol` 0..16, 16..32 == child-R's; 32.. = pad consts.
  3. **Root squeeze == `pv(root)`** — root perm `ocol` 0..16 == `pv(2·n_opvs+k)`.
  Argument: (1)+(2)+(3) force the trace's sponge output == the fixed public
  `pv(root)` = `merge_root(honest opvsL, opvsR)`. A valid keccak sponge hitting a
  fixed digest ⇒ its message == the honest preimage (preimage resistance) ⇒ the
  free rate messages == opvsL/opvsR. The cap comparison independently binds
  `pv(opvsL/opvsR)` to the children, so `pv(root)` (block-body-supplied) being
  `merge_root(pv(opvs))` closes the loop. **No `msh` per-block one-hot, no rate
  binding.** Markers needed shrink from `nm≈89` to ~5 WIDE-ONLY columns: `mreg`
  (region) + `mcnt` (pin) + a `sponge-start` flag (the 3 reset perms) + `dL/dR`
  source-perm flags + a root-perm flag — all at FIXED offsets within the merge
  region (derivable from `mcnt`).
  **Tradeoff:** relies on keccak preimage resistance (already the system's
  security foundation) rather than a constraint-level bind. **Flag for coordinator
  soundness review** — if they want the unconditional bind, add the `msh` message
  binding back (the ~89-col path above). Recommend root-binding-only: standard for
  hash-based, far cheaper, keeps the tree-merge (spec C4) intact.
  **Even simpler alt (if coordinator OK deviating from C4's tree-merge):** a FLAT
  sponge over `opvsL ‖ opvsR` → root (one continuous chain, ONE reset, root = last
  perm output) needs only `mreg` + root-perm flag (~3 cols) — but redefines 棒 3-1's
  `merge_root` (currently tree `keccak(keccak(opvsL)‖keccak(opvsR))`) + updates
  `interior_merge_native`. Keep tree-merge unless the coordinator prefers flat.

- [ ] **Step 2: Failing merge-binds test.**
```rust
#[test]
fn interior_merge_binds_root() {
    let _g = heavy_lock();
    let (sl, sr, ol, or) = crate::m4interior::two_child_schedule(true);
    let (trace, meta) = build_interior_trace(&sl, &sr, &ol, &or, &GateShape::wide(), 0);
    // meta.opvs[..] == keccak-merge(digest(ol), digest(or)); check_constraints passes.
    check_constraints(&VerifierGateAir::new_with_shape(GateShape::wide()), &trace, &meta.opvs);
    assert_eq!(meta.opvs, crate::m4interior::merge_root(&ol, &or));
}
```

- [ ] **Step 3: Run, expect FAIL then implement** the merge sponge in eval (LaneBuilder perm + bind the exposed root against `meta.opvs`). Run: `cargo test --release -p qlab-bench interior_merge_binds_root -- --nocapture 2>&1 | tail -12`.

- [ ] **Step 4: Failing wrong-merge negative.**
```rust
#[test]
fn interior_neg_wrong_merge() {
    let _g = heavy_lock();
    let (sl, sr, ol, or) = crate::m4interior::two_child_schedule(true);
    let l = GateLayout::from_shape(&GateShape::wide());
    let (base, _m) = build_interior_trace(&sl, &sr, &ol, &or, &GateShape::wide(), 0);
    let mut t = base.clone();
    let mut o = crate::m4interior::merge_root(&ol, &or);
    o[0] += Val::ONE; // root != merge(dL,dR)
    assert!(is_unsat_wide(t, o), "wrong merge root must be UNSAT");
}
```

- [ ] **Step 5: Run negative, expect UNSAT (test ok).** Run: `cargo test --release -p qlab-bench interior_neg_wrong_merge -- --nocapture 2>&1 | tail -8`.

- [ ] **Step 6: Full suite green + commit.**
```bash
git add crates/qlab-bench/src/m4gate.rs crates/qlab-bench/src/m4interior.rs
git commit -m "feat(m4interior): keccak merge sponge -> interior root (binds + wrong-merge negative)"
```

---

## Task S3 (stage 3): peak-RSS measurement vs 32 GB

**Files:**
- Modify: `crates/qlab-bench/src/m4interior.rs` (`run_m4interior` full-`prove` + RSS), `crates/qlab-bench/src/main.rs` (dispatch arm)
- Docs: `docs/m4interior-stage3-run{1,2}.md`

- [ ] **Step 1: `run_m4interior`** — mirror `m4gate`/`m4treerec` bench: build the two-child interior (distinct), `prove` at b4, capture prove time + peak RSS + fixed bytes. Print `print_env`.

- [ ] **Step 2: Dispatch arm** in `main.rs` after `"m4tree"`. Run: `cargo check -p qlab-bench 2>&1 | tail -3`.

- [ ] **Step 3: Measure (heavy, foreground).** Run: `cargo run --release -p qlab-bench -- m4interior 2>&1 | tail -30`. Record prove time, **peak RSS**, bytes.

- [ ] **Step 4: Reproduce twice** (bench discipline). Write both runs to `docs/m4interior-stage3-run{1,2}.md` with git rev / prover revs / hardware / OS / power.

- [ ] **Step 5: Compare vs §6** (≤ 30 s / ≤ 32 GB). Inside → report to coordinator (tests + bench + diff → merge). Over < 2× → fallback (i) b2 / (ii) k-tx. Over ≥ 2× → STOP, write numbers, flag design re-open + fallback (iii) Poseidon2-interior (labelled). Do NOT touch design repo.

- [ ] **Step 6: Commit.**
```bash
git add crates/qlab-bench/src/m4interior.rs crates/qlab-bench/src/main.rs docs/m4interior-stage3-run1.md docs/m4interior-stage3-run2.md
git commit -m "feat(m4interior): stage-3 two-child prove peak-RSS measurement vs 32 GB"
```

---

## Self-Review (spec coverage)

- Row-stacking / convergence — Architecture + 2a/2c. ✅
- Lane-driven 2^19, no bank parallelism — Global Constraints + 2c Step 2. ✅
- `emit_child` extraction, byte-identical — 2a. ✅
- csel constraint-pinned + negative — 2b (Steps 2/4) + `gate_neg_csel_narrow`. ✅
- Degree reduction ≤ 3 — 2b Step 6 + guard. ✅
- Two opvs binding — 2c Step 2 + 2d child-R opvs negative. ✅
- Merge sponge + binds/wrong-merge — Task 3. ✅
- Distinct children HARD PR-gate — 2d Steps 1/4. ✅
- Per-child negatives (both lanes bound) — 2d. ✅
- Stage-3 RSS gate + stop-rule — Task S3. ✅

**Note (honest):** slice 2b's exact eval expressions per anchor site are discovered in-situ (dozens of `when_first_row`/carry sites); each step's *acceptance gate* (suite green / csel negative UNSAT / degree ≤ 3) is concrete, per the peel-the-onion precedent. 2c/3 SAT tests may surface further wide-shape layers to peel (diagnose via `dump_constraint`), each its own sub-commit.
