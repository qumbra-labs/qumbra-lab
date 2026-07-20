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

## Status & handoff (updated 2026-07-19)

**棒 1a — DONE** (narrow→wide re-parametrization foundation; narrow behaviour
unchanged, all narrow tests green, independently re-verified):
- `7454a22` staged plan.
- `49c9474` slice 1a-i: `GateShape` narrow/wide + `gate_shape_narrow_reproduces_consts`.
- `383e17e` slice 1a-i-b: `GateLayout::from_shape` reproducing the ~130-entry
  offset chain + `gate_layout_narrow_reproduces_consts`.
- `45a3b73` slice 1a-ii: `VerifierGateAir` carries `shape`/`layout`; `eval`
  (925 subs) + builders (`write_row`/`bank_*`/`fill_fs_row`/`fill_canon`/
  `fill_derived` gained `&GateLayout`) read them; `build_gate_trace` public
  signature unchanged (derives narrow internally); `new_with_shape(shape)` added
  (unused). Gate: `cargo test -p qlab-bench m4gate` = 35 passed (incl. heavy
  `gate_rectangle_satisfies` + 19 negatives); whole crate 50 passed.

**棒 1b — IN PROGRESS.**
- `5bd5a53` investigation `docs/m4-1b-wide-params-investigation.md`: derived +
  empirically confirmed every wide transcript/layout param (QSLOTS 165,
  N_SHAPES_OBS 46, N_CHALS 6, N_GROUPS 48, N_ROLES 12, N_MICROS 15, N_FHG 21,
  DRND 5, flush geometry), the builder/trace refactor site list, and the
  `build_gate_trace` shape-param sketch. **Correction:** N_CHALS/N_GROUPS/
  N_ROLES/N_MICROS are shape-varying, not fixed.
- `a58f754` slice 1b-1: `GateShape` now derives all those counts (each
  reproduces its narrow const); `GateLayout::from_shape` is fully shape-driven →
  `from_shape(wide())` yields correct wide *offsets*. Tests
  `gate_shape_derived_counts_narrow` + `gate_shape_wide_values`.

**棒 1b — 1b-2 / 1b-3 DONE; wide build BLOCKED by two circuit-design gaps
(1b-4 finding).**
- `0e3f465` slice 1b-2: `qprogram_from_shape`/`gate_consts_from_shape` (Vec-based
  GateConsts, `GateShape.log_blowup` added), `fhg_index` shape-aware, `Regs`
  runtime-sized, `eval` reads the group/chal/role/micro anchors from `self.shape`.
  Narrow byte-identical (37 pass, heavy suite green, 13.7 GB).
- `a3322e0` slice 1b-3: `build_gate_trace(sched, inner_pvs, shape, extra_bits)`;
  rectangle height = `(n_perms*24).next_power_of_two()` (narrow 2^16; wide 2^18);
  `new_with_shape` uses the shape-parametrized generators. Narrow green.

**⚠ 1b-4 FINDING — the wide single-child trace is UNCONSTRUCTABLE with today's
machinery** (probed via `qprogram_from_shape(&wide())`, upstream of any
`check_constraints`, so nothing "fires" — the trace can't be built). The
re-parametrization (棒 1a + 1b-1..1b-3, all mechanical + green) is done; the
*remaining* wide work is two genuine circuit EXTENSIONS, each ≈ the original
fold-pipeline build in scope — NOT loop-bound tweaks:

- **1b-A — generalize the leaf-sponge fresh-word roles.** Absorb roles hardcode
  narrow fresh-word counts (`R_ABS_C5`=5 trace-last, `R_ABS_C30`=30 fold-last,
  `R_ABS_F16`=16 quotient). Wide needs a **22-fresh** trace-last block and an
  **8-fresh** quotient block (panic: "no absorb role for a last block with 22
  fresh words", `m4gate.rs:1365`). The fresh count is baked into `eval`'s
  sponge-carry constraints (C5→carry limbs 12..100 + pad; C30→60..100),
  `role_range` (`rle(16)`/`rle(7)`/`rle(14)`), and `write_row`'s `(m0,m1)`
  ranges. Fix: parametrize the fresh count (carry it in the descriptor / derive
  the carry+pad ranges from it) so any last-block fresh count works.
- **1b-B — micro-op scheduling for a short last fold round.** Wide
  `path_levels=[15,15,11,7,3]`: the last fold round has only 3 path levels → 2
  interior slots (l=0,1), but `M_HORN` (final-poly Horner, the fold-chain END
  endpoint) needs l=2. Fix: relocate `M_FIN`/`M_HORN` off the last fold round
  (onto the quotient/trace path or a dedicated tail perm) so the END pin has a
  host on the wide query program.

**1b-A — DONE** (`c5109b7`, narrow 37 green / 432 s, byte-identical): leaf-sponge
fresh-word counts generalized by shape (no new roles — `N_ROLES`/layout
unchanged). `R_ABS_C5` carry `[2f+2·(f&1), 100)` with pad `[2f,2f+2)` iff f odd
(`f = tw mod 34`, narrow 5 / wide 22); `R_ABS_F16` zero-region `(2·qw)..100`;
`emit_leaf` picks the last-block role by leaf context (removed the
remainder-literal panic); `role_range`/`write_row` `(m0,m1)` = `(ceil(f/2)-1,
floor(f/2)-1)` per role (reproduces narrow: only C5's odd f differs m0≠m1); and
the **PX0 trace-leaf-end capture** (eval `sf(3)` + trace `r==3`) generalized to
`(f+1)/2` — it encoded f=5, would have been a latent wide bug. `qprogram_from_shape(&wide())`
now returns len 165 without panic; the wide trace builds past the sponge blocker.

**⚠ PEEL-THE-ONION: the wide build is a CHAIN of narrow-hardcoding removals.**
After 1b-A the wide `build_gate_trace` advances and stops at the **next**
blocker: `m4gate.rs:3645`, the challenger **observation-flush shape automaton**
— `shape drift at flush 0 block 6 (derived 6 vs expected 5)`, driven by wide
F0's block count (`n_pvs=852` → 28 blocks vs narrow 5). So the remaining wide
work, discovered incrementally (each fix reveals the next narrow assumption):
- **1b-B1 — flush-shape automaton — DONE** (`c033274`, narrow 37 green /
  373 s, byte-identical). `shape_list`/`shape_mosaic`/`shsel_index` now take
  `&GateShape` (shsel_index threads the cached `GateConsts::flush_blocks` slice
  — zero-alloc in the eval hot path); final-flush index `7 → 3 + n_fri_rounds`
  (= `flush_blocks.len()-1`), obs-flush count `8 → n_obs_flushes`, `FLUSH_BLOCKS[·]`
  → `self.consts.flush_blocks[·]`, F0 `Pv` mosaic spread by `n_pvs` (852 over 28
  blocks). fring ring width 8 / bidx one-hot width 6 kept (wide fits). Wide build
  now walks all obs flushes (F0..F6 + refills, no shape drift) + phasegate.
- **1b-B2 — reduced-opening / dup-phase asm (NEW next blocker).** After 1b-B1
  the wide build enters the F2-duplicate replay (855 dup blocks) and stops at
  **`m4gate.rs:~4129`** — `A0 capture = PZ0`, the F2-dup PZ-capture hardcoded at
  dup-block position `(72,14)` with `zvi == TW` (617). The reduced-opening asm
  (dup-block positions `148`/`147`/`(72,14)`/`(145,7)`, `TW`-tied capture rows)
  is narrow-hardcoded and must be derived from the wide zeta-group widths
  `[3626,3626,8]` / `flush_blocks[2]`=855. (This is the M_RO / PZACC / capture
  machinery — the fold-chain START endpoint side.)
- **1b-B2 — reduced-opening dup-phase captures — DONE** (`f10c309`, narrow 37
  green / 350 s, byte-identical). Added `GateShape::dup_captures() ->
  [(block,row,blkcnt);3]` from the clean formula: value → 4 u32 words, block =
  34 words = 17 value-rows, F2 opens with a 32-byte (8-word=4-row) digest
  prefix, so after `v` values the row is `g = 4 + 2v`, block `g/17`, row `g%17`,
  `BLKCNT = N − g/17` (`N = flush_blocks()[2]`). Reproduces every narrow literal:
  A0 (v=tw=617) → (72,14)/CMPA=76; A1 (v=2tw) → (145,7)/CMPB=3; A2 (v=2tw+qw) →
  (147,5)/BLKLAST=1; CMPC=N=148. Wide (tw=3626, N=855): A0 (426,14,429), A1
  (853,7,2), A2 (854,6,1). Generalized CMPA/CMPB/CMPC targets, capture row
  selectors, `zvi==tw`/`2tw`/`2tw+qw`, czd last-block `rle(row_A2−1)`, dup-entry
  BLKCNT reload, dup-last-block digest binding. `P0R/P1R` exponents were already
  dynamic (captured from `preg`, cross-checked vs `sched.alpha_off`) → wide-correct.
- **1b-B3 Part 1 — fold-round micro loops → `n_fri_rounds` — DONE** (`2c24996`,
  narrow 37 green, byte-identical). Root cause of the 4385 panic: `eval`/
  `build_gate_trace`/`fill_derived` dispatched on the narrow micro constants
  (`M_S0..M_S3`=4..7) while wide uses compressed numbering (`m_s`=4..6, `m_b`=7..9,
  `m_fhi`=10..12, `m_fin`=13, `m_horn`=14) → wide `7`=`m_b(0)` matched narrow's
  `M_S` arm → `rf=3` → `lf()[3]` OOB. Fixed: every fold-round loop/dispatch driven
  by `shape.n_fri_rounds()`/`lf()`/`cum()`/`path_levels()`/`log_arities`/`m_s(r)`/
  `m_b(r)`/`m_fhi(r)`/`r_plast_f(r)`; `M_FHI` pairs from `2^(la-1-l)`. Wide fold
  pipeline now runs to completion on a real wide schedule (s-chain, inv2s, breg
  ladder, fold output, reduced opening, x_fin chain all pass).
- **1b-B3 Part 2 — `M_HORN`/`M_FIN` placement — DESIGN FORK, DECIDED = Option A.**
  Part 1 made the wide build complete WITHOUT panicking, but `M_HORN` is silently
  **never scheduled** in wide (`x0`) → the fold-chain END endpoint pin
  (`RUNEV == Horner(final_poly, x_fin)`, guarded by `gate_neg_fpreg`) is ABSENT →
  a soundness hole, not a build failure. Cause: wide last round `path_levels`=3 →
  interior slots l=0,1 only; narrow hosts M_FHI@l0/M_FIN@l1/M_HORN@l2 but wide has
  no l2. **Decision: Option A** — relocate `M_FIN` to a spare `M_NONE` interior
  slot in an earlier wide round (rounds 0/1 have spares; `M_FIN` = x_fin product
  over index bits, no fold-chain dependency, eval gate keys only on its micro
  selector, `xfin` is a carried register) and place `M_HORN` at wide last-round
  l1 (still after last-round M_FHI@l0, so RUNEV is final). No QSLOTS change,
  shape-conditional so narrow stays byte-identical. (Rejected: Option B dedicated
  tail perm → changes qslots()=165 + ring width; Option C M_HORN on R_PLAST_F
  perm → untested bank-row interaction.) **Soundness diligence for the
  implementer:** verify `XFIN` not clobbered between the relocated `M_FIN` and the
  last-round `M_HORN`; the wide END-pin must be present and the wide
  `gate_neg_fpreg`/`_xfin_chain`/`_bad_fold` negatives must bind (in 1b-5). Code:
  `qprogram_from_shape` last-round `m4gate.rs:1458-1488`; END-pin eval
  `m4gate.rs:3113-3167`.
- **1b-B3 Part 2 — DONE** (implemented Option A; narrow byte-identical). Wide
  now schedules `M_HORN` exactly once (was 0) via a shape-conditional last-round
  emission: `last_has_fin = (path_levels[last]-1) >= 3` (narrow 4 → true, wide 2
  → false); narrow keeps M_FHI@l0/M_FIN@l1/M_HORN@l2; wide puts M_HORN@l1 and
  relocates `M_FIN` to round-0 l3 (`fin_reloc = Some((0,3))`). `M_FIN` has no
  fold-chain dependency (x_fin = ∏ index bits, carried `xfin` register).
- **1b-4 ATTEMPTED — wide `check_constraints` NOT yet SAT** (test
  `interior_single_child_satisfies`, `#[ignore]`'d). The wide trace now BUILDS
  fully (all peel-the-onion build blockers cleared through 1b-B3), but
  `check_constraints` fires at the next layer:

**1b-B4 — M_X1 x-chain + `log_max`-keyed bounds (NEW next blocker).** Panic
`m4gate.rs:2609`: `for r in 0..22` (narrow `LOG_MAX`) indexes `self.consts.kx`
whose wide len = `log_max`=18 → OOB at r=18. The M_X1 x-chain (query LDE eval
point x = ∏ over index bits) and its neighbours hardcode narrow `log_max`/`log_max-1`:
the `0..22` kx loop + `sf(21)` chain cap (this x-chain block ~2604-2626), plus
the `0..19` dmux path-direction loops (eval ~1866 / fill ~3710) and the
`idxb+19/20/21` cap-element selectors that 1b-B3 flagged as out-of-scope. Wide
`log_max`=18, `log_max-cap_height`=15. Generalize all to `self.shape.log_max`
(and `-1`/`-cap_height` as appropriate). Then re-attempt 1b-4 (enable the
`#[ignore]`'d test) — likely reveals the next layer or reaches SAT.

  **1b-B4 — DONE** (`db63823`, narrow 37 green, byte-identical): generalized to
  `self.shape.log_max` / `log_max-1` / `log_max-cap_height` (M_X1 x-chain kx loop
  + chain + cap, dmux, cap-element `idxb+capb+{0,1,2}`); cleared the M_X1 OOB.

  **BUILD-BLOCKER CHAIN CLEARED — the wide trace now BUILDS fully** (no panic/OOB
  anywhere in build + the full symbolic `check_constraints` pass). Work shifts
  from "make it build" to "make it satisfy":
  - **1b-B5 — row-0 constraint mismatch: DIAGNOSED (root cause nailed,
    symbolically, no prove).** Wide `check_constraints` reports **row 0:
    constraints #4174/#4176/#4179 unsatisfied**. Diagnosed via
    `get_symbolic_constraints` on `new_with_shape(wide())` (deg 3, no FIRST/TRANS
    flag): they are the **shsel-definition constraints for F0 blocks 7 / 9 / 12**
    — `shsel[F0_b] == chlive · ringsel(0) · bidxsel(b)` (eval ~2069), where
    `bidxsel(b) = cv(self.layout.bidx + b)`. **Root cause: `bidx` is a width-6
    saturating one-hot, but wide F0 has 28 blocks** (narrow F0 = 5, so narrow's
    `bidxsel(b≤4)` stays inside bidx's 6 slots; F2's 148/855 blocks are handled
    specially via `f2sel`+`blklast`, not per-block bidxsel). For wide,
    `bidxsel(b≥6)` reads OOB into neighbouring columns: b=7→`cmpai`(3073),
    b=9→`cmpbi`(3075), b=12→`shsel[0]`(3078) — all nonzero on row 0 → mismatch
    (blocks 6/8/10/11 hit row-0-zero columns, so check_constraints only surfaced
    7/9/12). This is the "positional-Pv" gap 1b-B1 flagged: F0's 28 blocks each
    carry a distinct Pv mosaic → each needs a distinct shsel selector → bidx must
    address all of them, but it caps at 6.
    **FIX (structural, ≈1b-B1 scale):** make `bidx` width shape-derived to cover
    the largest non-F2 flush's block count — `max over non-F2 flushes of
    flush_blocks + 1` (narrow max=5 → 6, byte-identical; wide max(F0)=28 → 29) —
    and de-saturate / shape-drive its block-index automaton (first-row,
    transition rotation, saturation cap) so `bidxsel(b)` is a valid per-block
    indicator for b up to 28. Layout note: widening bidx shifts all columns after
    it *for wide only* (narrow bidx stays 6 → narrow byte-identical). Also audit
    the `ring_at(fring, 8, ·)` sites (1746/2050/3752/4769/4772) — the `8` is the
    fring rotation modulus (= n_obs_flushes; narrow 8, wide 7); confirm whether
    the fill uses mod-8-physical (consistent, leave) or must be shape-derived.
    Then re-run wide `check_constraints` (may reveal further rows), enable the
    1b-4 test → wide single-child SAT → 1b-5 wide negatives → 棒 2 / 棒 3 / stage 3.

    **check_constraints peel-the-onion progress (wide 1b-4, row it fails at →):**
    - B5 (`90c3f48`) bidx one-hot width shape-derived (narrow 6 / wide 29) →
      cleared row-0 F0 shsel (#4174/76/79). Diagnosis in `feb897f`.
    - B6 (`0ee68e1`) caps8 fill `idx>>19` → `idx>>(log_max-cap_height)` (the
      fill-side counterpart to B4's eval cap-element); + a `WIDE=1 CIDX=n
      cargo test dump_constraint` toggle to inspect wide-AIR constraint indices.
      Cleared row 42216 (#3735/39). **fring `ring_at(...,8,...)` `8` = physical
      ring size, consistent fill+eval → LEAVE (confirmed).**
    - B7 (`e45ea9d`) DRND selector loop `0..6` + `fold_dp` drnd+2..+5 →
      `drnd_width()` / `0..n_fri_rounds` (wide drnd+5 = dbit OOB). Cleared row
      44808 (#3620).
    - Each B5–B7: narrow 37/37 byte-identical. Wide fail row advanced
      **0 → 42216 → 44808 → 200616 (~76% of the 2^18 trace)**.
    - **NEXT: 1b-B8 — row 200616, constraint #5187** = the fold-leaf **VC/HIT
      value-counter** region (touches vc[0..15], hit, glo/ghi GPB pair products)
      — a deeper fold-pipeline subsystem, likely NOT a width hardcoding; diagnose
      *why* wide fails (read the VC/HIT eval + fold-leaf value-matching), not just
      what it touches. **The M_HORN/RUNEV endpoint region (Option A, soundness-
      critical) is past row 200616 and not yet check-validated** — expect more
      fold-region layers before wide SAT. Diagnose: `WIDE=1 CIDX=5187 cargo test
      dump_constraint -- --nocapture` (colname prints NARROW names — map raw
      indices against the WIDE GateLayout the toggle dumps).
- **… likely more** surface as each is cleared. Each is moderate circuit work
  (narrow suite green + wide-build-advances-further as the per-slice gate); the
  whole chain is the "≈ fold-pipeline build" scope the 1b-4 finding flagged.

Only after the whole chain does 1b-4 (`interior_single_child_satisfies` via
`check_constraints`) become attemptable, then 1b-5 (wide negatives), then 棒 2/3.

**Original remaining-list (1b-2…1b-5), now partly superseded above** — spec'd by
the investigation report's §3 site list + §4 sketch. The AIR's `eval` and the
trace builders still read the narrow module consts + narrow generators, so a
wide trace can't be built yet:
- **1b-2 (invasive):** convert the builder/trace compile-time arrays & loops
  (`[u32; NQ]`, `[_; N_FHG]`, `0..4` fold rounds, `% QSLOTS`, `FLUSH_BLOCKS[f]`,
  `for f in 0..8`, `betas[0..3]`, the group/chal/role/micro anchors `G_POW/
  G_IDX0/G_DONE/N_FLUSH_ENTRIES` that eval still reads as consts) to runtime,
  sized from `shape`/`layout`. `qprogram()`→`qprogram_from_shape`,
  `gate_consts()`→`gate_consts_from_shape` (inner degree_bits = log_max −
  log_blowup; per-round `lf`/`kf`), `fhg_index` shape-aware. Narrow suite stays
  green as the gate.
- **1b-3:** `build_gate_trace` gains a `shape: &GateShape` param; relax the
  `assert_eq!(rows, 1<<16)` → shape-derived (wide interior ≈ 8,360 native perms
  → **2^18**). `new_with_shape` uses the shape-parametrized generators.
- **1b-4:** `interior_single_child_satisfies` — `check_constraints` on the 2^18
  wide trace (~4 GB, cheap, no full prove) from `m4treerec::walk_leaf` + wide().
- **1b-5:** re-derive the shape-tied negatives for the wide trace.
Optional heavy canary: one b4 single-child `prove` + peak-RSS (forecasts the
two-child breach).

(historical) The three blockers as first surfaced by 1a-ii:
1. **Const-array-size refactor (the real work).** Builder structs use compile-time
   sizes `[u32; NQ]`, `[Val::ZERO; N_FHG]`, and bare `0..4` fold-round literals.
   For wide, NQ 20→40, N_FHG 22→21, fold rounds 4→3. Convert these to runtime
   (`Vec`/`SmallVec`, or size to `max(narrow,wide)` with a used-len) so one code
   path serves both shapes. This is the invasive part — do it behind the green
   narrow suite (must stay green).
2. **Derive the wide transcript params** `QSLOTS` (per-query program length) and
   `N_SHAPES_OBS` (obs-shape selectors), currently narrow consts (103 / 26).
   Read them off the wide leaf `Schedule` (`m4treerec::walk_leaf` output) and
   lift into `GateShape` + `GateLayout::from_shape`; also confirm the fold-family
   widths (`breg` = n_rounds×4, `drnd`, GF/BPM/SNL). Update
   `gate_layout_narrow_reproduces_consts` to still hold and add a wide-shape
   layout sanity assert.
3. **Parametrize `build_gate_trace` by shape** (or add `build_gate_trace_wide`)
   so `new_with_shape(GateShape::wide())` gets a matching wide trace; then
   `interior_single_child_satisfies` = `check_constraints` on the 2^18 wide
   trace (~4 GB, rig-runnable, cheap — NOT a full prove). Re-derive the
   shape-tied negatives (`gate_neg_mro/_pzacc/_preg/_capture/_fpreg/_tampered/
   _wrong_root/_wrong_query_index`) for the wide trace.
Optional heavy canary after SAT: one b4 single-child `prove` + peak-RSS read
(forecasts the two-child breach — see the quantified-risk section).

## Open decisions for the executing session

1. If Task 1a-ii's in-place refactor balloons past a session, the recorded
   fallback is a copied `m4wgate.rs` specialized to `wide()` — accept the
   duplication to keep the shipped leaf untouched. (Preference: in-place
   re-parametrize per the handoff; copy only if the refactor won't converge.)
2. If two-child b4 `prove` exceeds the 36 GiB rig, correctness stays validated
   via `check_constraints` (already config-independent); the b4 *measurement*
   moves to a higher-RAM rig or triggers the fallback-(i) b2 path — a stage-3
   decision, not a stage-2 blocker.
