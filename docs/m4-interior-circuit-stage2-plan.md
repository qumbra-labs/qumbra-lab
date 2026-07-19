# M4 step 1 stage 2 — interior verifier CIRCUIT: staged implementation plan

> **For agentic workers / relay sessions:** this is the relay artifact for a
> ~3-session build (analogue of `m4gate-inc4-status.md` for the leaf 0b(ii)).
> Execute task-by-task, **one commit per slice** (分棒是硬要求 — a giant WIP
> commit gets killed midway). Keep `cargo check` green and the existing narrow
> m4gate tests green on every commit. Steps use checkbox (`- [ ]`) syntax.

**Goal:** re-parametrize the `m4gate` verifier machinery from the M3 *narrow*
inner-proof shape to the *wide* leaf-proof shape, and build the interior
aggregation node's in-circuit verifier: **2 children + a public-digest merge**,
then measure its peak RSS against aggregation-rung1 §6's ≤ 30 s / ≤ 32 GB
interior envelope.

**Architecture:** the uni-stark FRI verification *algorithm* is identical for
narrow and wide inner proofs — only the inner proof's **shape parameters**
differ (trace width 617→3,626, queries 20→40, FRI rounds 4→3, caps 6→5,
degree-bits 18→16, group offsets a^617→a^3626, path levels, flush geometry,
inner public-value set). The recorder (`m4gaterec::walk_with_cfg`) is *already*
shape-agnostic and records the wide leaf proof (proven by
`m4treerec::recorder_accepts_leaf`). **All stage-2 work is on the circuit side**
(`m4gate.rs`): convert its ~40 top-of-file shape `const`s and flat
column-offset chain into a `GateShape` + `GateLayout` the AIR reads at runtime,
instantiate `narrow()` (the existing leaf, unchanged behaviour) and `wide()`
(the interior), then compose two wide children + a merge.

**Tech stack:** Rust 2021, Plonky3 0.6.1 (pinned), KoalaBear field, stock
`p3-keccak-air` via `m4skel::LaneBuilder`, `p3-uni-stark` prove/verify.

---

## Global constraints (copied verbatim from the handoff)

- **分棒是硬要求.** One commit per testable slice. No giant single commit — this
  is the 0b(ii) magnitude that blew the quota 3×. leaf-verify / interior-circuit
  / merge-digest are the coordinator's three mandated 棒; sub-slices within each
  are encouraged, not discouraged.
- **32 GB is a real gate, not a formality.** aggregation-rung1 §6: interior
  ≤ ~30 s / ≤ 32 GB. If measured **over by ≥ 2× → STOP**: write the measured
  numbers, do **not** force it; flag the design-doc re-open and the fallback
  ladder (i) per-level config tuning → (ii) k-tx leaf batching → (iii)
  explicit-trust Poseidon2-interior (labelled, never silent). Over by < 2× →
  fallback (i)/(ii) tuning round.
- **Do NOT touch the design repo.** `qumbra-design` measured-updates are
  coordinated by the main session. This branch only touches `qumbra-lab`.
- Bench discipline: any published number is reproduced twice on the same rig,
  carries git rev / prover revs / hardware / OS / power state.

## The core risk, quantified (read before scheduling the heavy runs)

Height is the dominant RAM driver, and uni-stark requires a power-of-2 height,
so padding compounds it:

| circuit | lane perms (measured/derived) | min rows (×24) | padded height | rel. cells vs leaf |
|---|---|---|---|---|
| leaf gate (M3 verifier) — **measured 11.9 GB / 0.67 s @ b4** | 2,382 | 57,168 | **2^16** | 1.0× |
| 棒 1b single wide child | ~7,503 | 180,072 | **2^18** | ~4.1× |
| 棒 2 two children + merge | ~15,006+ | ~360k+ | **2^19** | ~8× |

Two independent projections bracket the interior RAM and **disagree**, which is
exactly why §6 makes this a measured gate:

- aggregation-rung1 §4 (optimistic, keccak-lane cells only, no pad): two
  children ≈ 0.95 G cells → **LDE 13–18 GB @ b4**.
- Height-padded, full 3,626-col rectangle scaled from the *measured* leaf:
  single child **~20–30 GB**, two children **~32–64+ GB @ b4** — at or over the
  envelope, and plausibly over the 36 GiB rig's physical RAM.

**Consequence for the build:** correctness (SAT for genuine, UNSAT for tampered)
is checked with `check_constraints` over the **raw trace only** (no ×blowup LDE,
no commitment) — ~230 MB at 2^16, ~4 GB at 2^18, ~8 GB at 2^19: **always
runnable on the rig**. Only the full `prove` (stage 3) hits the LDE wall.
**So: land all of stage 2's correctness via `check_constraints`; do the single
heavy `prove` measurement in stage 3.** 棒 1b's single-child `prove` is the
early canary — if it already sits near ~30 GB, two-child will breach and the
stop-rule triggers before 棒 2 is even worth proving at b4.

---

## File structure

- **Modify:** `crates/qlab-bench/src/m4gate.rs` (4,689 lines) — introduce
  `GateShape` + `GateLayout`; make `VerifierGateAir` carry them; replace the
  const-offset chain and the `NQ`/`TW`/round-count literals in `eval`,
  `qprogram`, `gate_consts`, `lane_plan`, `build_gate_trace`, `outer_pvs` with
  shape/layout reads. Existing `const NARROW_*` values become
  `GateShape::narrow()`.
- **Create:** `crates/qlab-bench/src/m4interior.rs` — the interior node: build a
  two-child verification schedule (via `m4treerec`), assemble the two-child
  trace, the merge-digest, the `run_m4interior` bench mode. Analogue of
  `m4treerec.rs` but for the circuit.
- **Modify:** `crates/qlab-bench/src/m4treerec.rs` — add the deferred
  byte-exact keccak-sequence cross-check for the wide/leaf recorder (stage-1
  deferred item), mirroring `m4gaterec::walk_matches_native_hashing`.
- **Modify:** `crates/qlab-bench/src/main.rs` — declare `mod m4interior` (line
  ~24) and add the `"m4interior"` dispatch arm (after the `"m4tree"` arm,
  ~line 926).
- **Docs:** `docs/m4interior-stage2-run{1,2}.md` (stage 3 measurement),
  `docs/m4tree-step1a-run*.md` precedent for format.

## Edit surface (exact line numbers, from the structural map)

Shape literals to lift into `GateShape` (m4gate.rs): `TW=617` (114), `QW=16`
(116), `N_PVS=84` (118), `NQ=20` (120), `LOG_MAX=22` (121), `GRIND_BITS=20`
(124), `LOG_ARITIES=[4,4,4,2]` (126), `CUM=[0,4,8,12,14]` (127),
`PATH_LEVELS=[19,19,15,11,7,5]` (129), `N_CAPS=6` (132), `CAP_LEN=8` (133),
`FLUSH_BLOCKS/FLUSH_BYTES` (136,138), draw-group consts (142–151), `QSLOTS=103`
(183). Column-offset chain 392–584 → `GateLayout`. `P0R`=a^617 / `P1R`=a^1234
(513–514) → a^TW / a^2·TW. `gate_consts` `lf=[18,14,10,8]` + `kf`/`sk`/`g_trace`
(814–843). `qprogram` path loops `0..18` + fold `0..4` (692–758). eval fold/RO
blocks 2100–2440, PZACC/captures 2186–2279 (round-count `0..4`, `pairs3`,
`N_FHG=22`, S0/S1/S2 group widths). `lane_plan` 2522–2651 + height `assert
1<<16` (3097). `outer_pvs` 2499 + `LANE_CFGS` 3929.

Wide shape target values (from `m4treerec` + stage-1 run doc): TW=3,626, NQ=40,
FRI rounds=3 `LOG_ARITIES=[4,4,4]`, final-poly len 16, N_CAPS=5, degree-bits=16,
opened values/query=7,260 (two full 3,626 rows + 8 quotient), reduced-opening
290,400 = 40×7,260, 65 challenger draws, `PATH_LEVELS` re-derived for a 2^16
inner tree with 3 FRI rounds, inner public values = the leaf gate's `N_OPVS`.

---

## 棒 1 — leaf-verify (single wide child in-circuit)

### Task 1a-i: `GateShape` / `GateLayout` scaffolding + narrow-reproduction test

**Files:** Modify `crates/qlab-bench/src/m4gate.rs` (add types near the const
block, before line 380; add a unit test in the test module).

**Interfaces produced (used by every later task):**
- `struct GateShape { tw, qw, n_pvs, nq, log_max, grind_bits, log_arities: Vec<usize>, path_levels: Vec<usize>, n_caps, cap_len, flush_blocks: Vec<usize>, flush_bytes: Vec<usize>, qslots, degree_bits, ... }` (all `usize`/`Vec<usize>`; `pub(crate)`).
- `impl GateShape { fn narrow() -> Self; fn wide() -> Self; }` — `narrow()`
  returns exactly the current M3 const values; `wide()` returns the leaf-proof
  values above.
- `struct GateLayout { /* every former column-offset const as a usize field */ gate_width, mul_off, add_off, gb, grp, coef, chal, idxr, qsel, /* … */ fpi }`
  with `fn from_shape(&GateShape) -> GateLayout` computing the offset chain.

- [ ] **Step 1 — failing test:** add `fn narrow_layout_reproduces_consts()` to
  the test module asserting `GateLayout::from_shape(&GateShape::narrow())` field
  values equal the current `const`s (`TW==617`, `NQ==20`, `GATE_WIDTH`,
  `GB`, `GRP`, `COEF`, `CHAL`, `IDXR`, `QSEL`, `P0R`/`P1R` exponents, `FPI`,
  every offset). This pins that the runtime layout is byte-for-byte the old one.
- [ ] **Step 2 — run, expect fail:** `cargo test -p qlab-bench narrow_layout_reproduces_consts` → FAIL (types absent).
- [ ] **Step 3 — implement** `GateShape` + `GateLayout::from_shape` reproducing
  the 392–584 chain arithmetic from shape fields (no eval rewiring yet).
- [ ] **Step 4 — run, expect pass.** Also `cargo check --workspace` green.
- [ ] **Step 5 — commit:** `feat(m4gate): GateShape/GateLayout scaffolding, narrow reproduces consts`.

> This slice is pure-additive and light (no proving). It de-risks the entire
> refactor's arithmetic *before* touching `eval`. A relay session can safely
> pick up from here.

### Task 1a-ii: rewire `eval` + builders to read layout/shape (narrow behaviour unchanged)

**Files:** Modify `m4gate.rs` — `VerifierGateAir` holds `shape: GateShape,
layout: GateLayout` (from `new()` defaulting to `narrow()`); replace every
`CONST` column index in `eval` (879–2445), `qprogram`, `gate_consts`,
`lane_plan`, `build_gate_trace`, `outer_pvs` with `self.layout.*` / `self.shape.*`.

- [ ] **Step 1:** thread `shape`/`layout` through `VerifierGateAir::new()`
  (keep `new()` = narrow) and all builder fns. Arrays that change length
  (`log_arities`, `path_levels`, `flush_*`, fold `kf`/`sk`, `N_FHG`) read from
  `shape` Vecs; fixed-size groups (`pz:[Ext;3]`, `alpha_off:[Ext;2]` — 3 zeta
  groups for both shapes) stay arrays.
- [ ] **Step 2 — the safety gate:** run the FULL existing narrow test suite —
  `cargo test -p qlab-bench m4gate` (or `--lib m4gate::tests`). All ~27 tests
  (positive `gate_rectangle_satisfies` + 19 `gate_neg_*` + diagnostics +
  `constraint_degree_within_budget`) must stay green. Any offset misreference
  breaks a narrow test (narrow offsets are unchanged), so this is a strong net.
- [ ] **Step 3 — commit:** `refactor(m4gate): eval reads GateLayout/GateShape; narrow unchanged`.

> This is the largest, most mechanical slice — plausibly a full relay session.
> Split further if needed (e.g. eval-column reads / qprogram / lane_plan /
> build_gate_trace as separate commits, each with the narrow suite green).

### Task 1b: `GateShape::wide()` + single wide-child verifier

**Files:** Modify `m4gate.rs` (`wide()`, any wide-only branches); create
`m4interior.rs` (single-child assembly reusing `m4treerec::leaf_proof` /
`walk_leaf`); modify `main.rs` (mod + dispatch).

**Interfaces:** `m4interior::child_schedule() -> (Schedule, Vec<Val>)` (the wide
leaf proof's recorded verification + its opvs); `build_gate_trace` called with a
`VerifierGateAir::wide()` — reuse the existing `build_gate_trace` entry, now
shape-driven, with the height assert reading `1 << shape.degree_bits`-derived
rectangle height (2^18 for one wide child).

- [ ] **Step 1 — failing test** `interior_single_child_satisfies`: build the
  wide-child trace from a real leaf proof's schedule and `check_constraints`
  passes (config-independent, cheap — no full prove).
- [ ] **Step 2 — run, expect fail** (wide layout/qprogram not yet correct).
- [ ] **Step 3 — implement** `wide()` + the wide-shape branches in
  `qprogram`/`lane_plan`/RO-group-widths so the single-child rectangle is SAT.
- [ ] **Step 4 — run, expect pass.**
- [ ] **Step 5 — re-derive the shape-tied negatives** for the wide shape
  (`gate_neg_mro`, `_pzacc`, `_preg`, `_capture`, `_fpreg`, `_tampered_opening`,
  `_wrong_root`, `_wrong_query_index`): each must be UNSAT on the wide trace.
- [ ] **Step 6 — commit:** `feat(m4interior): single wide-child verifier (SAT + shape-tied negatives)`.
- [ ] **Step 7 — canary measure (optional, heavy):** one `prove` of the single
  wide child at b4; record peak RSS + time. If ~≥30 GB, note it loudly — it
  forecasts a two-child breach.

### Task 1c: wide recorder byte-exact keccak cross-check (stage-1 deferred item)

**Files:** Modify `m4treerec.rs` (+ possibly generalize `m4gaterec`'s test-module
`record_verify` to the wide AIR + AGG_CFG).

- [ ] **Step 1 — failing test** `walk_leaf_matches_native_hashing`: mirror
  `m4gaterec::walk_matches_native_hashing` (leaf-sponge/compress/challenger
  perms byte-equal a native replay) for the wide leaf recorder; expect the
  7,503 = 4,560 + 2,040 + 903 split.
- [ ] **Step 2–4:** generalize `record_verify` to accept the wide AIR + AGG_CFG;
  make it pass.
- [ ] **Step 5 — commit:** `test(m4treerec): byte-exact keccak-sequence cross-check for the wide recorder`.

---

## 棒 2 — interior-circuit (2 children in one rectangle)

**Files:** Modify `m4gate.rs` (two-child `lane_plan` scheduling both children's
verification programs; the 2^19 height; per-child opvs routing) and
`m4interior.rs`.

**Interfaces:** `m4interior::two_child_schedule() -> (Schedule, Schedule, [Vec<Val>;2])`;
`build_interior_trace(&sched_l, &sched_r, &opvs_l, &opvs_r) -> (trace, meta)`
producing a 2^19 rectangle with both children's lanes + both opvs sets bound.

- [ ] **Step 1 — failing test** `interior_two_child_satisfies`: two real leaf
  proofs verified in one rectangle, `check_constraints` passes (cheap; ~8 GB
  trace at 2^19 — fits the rig).
- [ ] **Step 2 — run, expect fail.**
- [ ] **Step 3 — implement** two-child lane_plan + routing + 2^19 height.
- [ ] **Step 4 — run, expect pass.**
- [ ] **Step 5 — negatives:** tamper child-L opening → UNSAT; tamper child-R
  independently → UNSAT (proves both lanes are bound, not just one).
- [ ] **Step 6 — commit:** `feat(m4interior): two children verified in one rectangle`.

## 棒 3 — merge-digest (public-input merge → root)

Per aggregation-rung1 §2: the interior root's public value binds a running hash
of the covered-tx digests of both children (`d_i` = each child's opvs /
public-input commitment), so a mismatch with the block body is detectable
without any proof.

**Files:** Modify `m4gate.rs` / `m4interior.rs` — add a merge-digest gadget
(keccak sponge over the two children's public-digest commitments → one root
digest exposed as the interior circuit's outer public value).

- [ ] **Step 1 — failing test** `interior_merge_binds_root`: root public value
  == keccak-merge(child-L digest, child-R digest); `check_constraints` passes.
- [ ] **Step 2 — run, expect fail.**
- [ ] **Step 3 — implement** the merge sponge (reuse the LaneBuilder keccak
  lane; the merge adds a handful of perms — negligible vs 15k).
- [ ] **Step 4 — run, expect pass.**
- [ ] **Step 5 — negative** `interior_neg_wrong_merge`: a root not equal to the
  merge of the two child digests is UNSAT.
- [ ] **Step 6 — commit:** `feat(m4interior): public-digest merge → interior root`.

---

## Stage 3 — measure interior peak RSS vs 32 GB (separate; the gate)

Not part of stage 2's commits; runs after 棒 3 lands. Add `run_m4interior`
full-`prove` path + RSS instrumentation (mirror `m4gate`/`m4treerec` bench
env-print + peak-RSS capture).

- [ ] Prove the full two-child interior at **b4** (and b2 if b4 breaches the
  rig); record prove time, **peak RSS**, aggregate bytes. Reproduce twice.
- [ ] Compare vs §6: interior ≤ 30 s / ≤ 32 GB.
  - **Inside** → tree prototype unblocked; report to coordinator (independent
    acceptance: test reproduction + bench + diff → merge → coordinator syncs
    design/ROADMAP/memory).
  - **Over < 2×** → fallback (i) per-level config (try b2 — lower blowup halves
    LDE) / (ii) k-tx batching; re-measure.
  - **Over ≥ 2×** → **STOP.** Write measured numbers to
    `docs/m4interior-stage2-run*.md`; flag design-doc re-open + weigh fallback
    (iii) explicit-trust Poseidon2-interior honestly. Do NOT force. Do NOT touch
    the design repo — hand the numbers to the coordinator.

---

## Self-review (spec coverage)

- §2 statement — leaf-layer verify (棒 1), interior verify children (棒 2),
  merge public-input commitments → root (棒 3). Epoch supply-rider = out of
  stage-2 scope (near-free once tree exists; a later step). ✅ covered.
- §6 envelope + stop-rule — stage 3 + the quantified-risk section. ✅
- Coordinator rule 1 (分棒) — one commit per slice, three named 棒. ✅
- Coordinator rule 2 (32 GB) — quantified risk + explicit stop-rule. ✅
- Coordinator rule 3 (no design repo) — stated in global constraints + stage 3. ✅
- Stage-1 deferred item (byte-exact keccak cross-check) — Task 1c. ✅

## Open decisions for the executing session

1. If Task 1a-ii's in-place refactor balloons past a session, the recorded
   fallback is a copied `m4wgate.rs` specialized to `wide()` — accept the
   duplication to keep the shipped leaf untouched. (Preference: in-place
   re-parametrize per the handoff; copy only if the refactor won't converge.)
2. If two-child b4 `prove` exceeds the 36 GiB rig, correctness stays validated
   via `check_constraints` (already config-independent); the b4 *measurement*
   moves to a higher-RAM rig or triggers the fallback-(i) b2 path — a stage-3
   decision, not a stage-2 blocker.
