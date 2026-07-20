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

- [ ] **Step 1: `leaf_proof_variant` (distinct child).** In `m4treerec.rs`, mirror `leaf_proof` but drive `consensus_proof` with a distinct instance (e.g. a second `BucketInstance` seed) so `opvs` differ. Verify `opvs_l != opvs_r`.

- [ ] **Step 2: Failing per-child + distinct negatives (TDD).** Add `interior_two_child_negatives` mirroring `interior_single_child_negatives`: build one interior trace (distinct children), clone-per-probe, assert UNSAT for: tamper child-L opening (`qrL[0]` region); independently tamper child-R opening (`qrR[0]` region, i.e. rows ≥ `24*nL`); tamper child-R opvs cap. Each proves the lane it targets is bound.
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

- [ ] **Step 3: Run, expect FAIL then implement** (extend `GateMeta` if needed so per-child query rows are distinguishable, e.g. `query_rows` already carries absolute rows — child R's are ≥ `24*nL`). Run: `cargo test --release -p qlab-bench interior_two_child_negatives -- --nocapture 2>&1 | tail -15`. Expected: all probes UNSAT → test ok.

- [ ] **Step 4: distinct-child SAT (PR-gate).** Also assert `interior_two_child_satisfies` passes with `two_child_schedule(true)` (add a `_distinct` variant test or parametrize). Expected: SAT with distinct children.

- [ ] **Step 5: Full suite green.** Run: `cargo test --release -p qlab-bench m4gate 2>&1 | tail -8`.

- [ ] **Step 6: Commit.**
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

- [ ] **Step 1: Compute the merge in the builder.** After both `emit_child` calls, append a keccak sponge perm (or few) absorbing `(dL, dR)` → root digest; store as `meta.opvs`. `dL/dR` = each child's covered-tx digest (define as the keccak of the child's opvs, matching aggregation-rung1 §2).

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
