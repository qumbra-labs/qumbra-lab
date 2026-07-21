# M4 step 2 — tree/root assembly + epoch supply-attestation rider (plan + recon)

Branch: `claude/m4-step2-tree` (worktree `../qumbra-lab-m4-step2`), base `main = 8861e29`.
Mandate: the §7.3 PASS row's next action (aggregation-rung1). Coordinator owns acceptance
+ the design repo; this session stages commits and opens a PR, does not merge, does not touch
the design repo or the consensus (`qlab-air` narrow/M3) circuit. GRIND_BITS unchanged (issue #22).

## Scope (from the builder prompt)

Three deliverables, two-level tree only:

1. **End-to-end tree driver** (new bench mode): two DISTINCT M3 tx proofs → prove two leaf
   proofs serially → prove the interior root proof → natively verify the full chain, which
   MUST include issue #24's consumer-side check as a **hard assertion** in the driver:
   `root_pv == keccak-merge(opvsL, opvsR)` recomputed natively. `--lane b4|b2` selects the
   interior FRI lane (b4/q40, b2/q80; both ~100 bits; per-level config is a design open item —
   the measured data informs it, we do not decide it).
2. **Epoch supply-attestation rider (prototype)**: the root's public face exposes a bound
   `Σ fee` over all covered transactions. Interior circuit extracts each child's fee from its
   `opvs`, constraint-sums, and exposes the sum as a new root public value. Negatives: tamper
   the exposed Σfee → UNSAT; tamper a child's fee source slot → UNSAT.
3. **End-to-end measurement**: whole-tree wall time (2 leaf + 1 interior) + per-segment proof
   size, b4 and b2 lanes both; interior-segment peak footprint. Runs → `docs/m4tree-step2-run{1,2}.md`.

Out of scope (hard redlines): ≥3-level tree / interior-verifies-interior (no scaffolding —
needs a new census + RSS gate + issue #24 closed first); the consensus circuit; the design repo;
GRIND_BITS. Optional side road (separate commit, only if time): 1c byte-level wide-keccak
cross-check generalising `m4gaterec::record_verify` (expected 7,503 = 4,560 + 2,040 + 903).

## Fee reconnaissance — VERDICT: PROCEED (fee is directly extractable AND constraint-bound)

The stop-point was: "if fee is not at an extractable position in leaf `opvs` (e.g. only inside
the M3 digest), stop and escalate ≤2 options — do not self-modify the leaf public face." It did
**not** trigger. Findings:

- The M3 narrow AIR exposes `fee` as **public values** `PV_FEE = 80 .. PV_LEN = 84` — four
  16-bit little-endian limbs (`qlab-air/src/narrow.rs:149-150`, `pv_vec` at `:159-175`). It is
  the clean **tail** of the 84 inner PVs (anchor 0..16, nf1 16..32, nf2 32..48, cm1 48..64,
  cm2 64..80, fee 80..84). The balance close binds `Σin = Σout + fee` in-circuit (`narrow.rs:682,707-720`).
- The leaf gate's outer public values `opvs` = **768 cap limbs** (6 caps × 8 digests × 16 limbs,
  `OPV_PVS = N_CAPS*CAP_LEN*16 = 768`) **+ 84 inner PVs** (`m4gate.rs:604-608`, `outer_pvs` at
  `:3702-3720`). So each child's fee limbs live at `opvs[OPV_PVS + PV_FEE + j] = opvs[848+j]`,
  j∈0..4 — a **direct value**, not folded only into a digest.
- Encoding: the inner PVs ride the outer interface in Montgomery-word transcript form
  (`opvs[768+i] = inner_pv_i * monty_rr()`, `m4gate.rs:3716-3717`, `monty_rr` at `:3871`). The
  whole verification pipeline is R-homogeneous, so operating on the scaled values is internally
  consistent; the rider's sum can be exposed in the same scaled representation (the design open
  item — direct value vs digest — is answered "direct value", recorded here for the coordinator).
- Binding: each inner PV is pinned by `WordBind::Pv(opv_pvs + i)` in challenger flush F0's word
  mosaic (`m4gate.rs:648-653`), i.e. constraint-bound to the transcript word the M3 proof
  actually absorbed. Therefore a tampered fee source slot breaks the child's transcript binding →
  UNSAT (negative #2 is achievable), and the summed rider is bound to the honest per-child fees.
- Interior already routes each child's opvs into the root pv via the `chi/cc` mux
  (`m4gate.rs:2324-2337`) and exposes `opvsL ++ opvsR ++ merge_root` (`n_opvs*n_children + merge`,
  `:1793-1796`). The rider is one more exposed pv + a sum constraint over already-routed slots —
  "arithmetic over public values the tree already carries," matching §2's "near-free."

Prototype note: §2's full rider is `Σ(coinbase) − Σ(fees burned)`; coinbase is block-level, not a
per-tx M3 PV, so the **prototype exposes Σfee** over the covered txs (the builder prompt's "Σ fee").
The coinbase term is a block-format concern for M6, not this circuit — noted for the design repo.

## Phase plan (each phase = clean commit; unfiltered `cargo test --release -p qlab-bench` green; deg ≤ 3 held)

- **Phase 0 (this doc)** — orient, recon, baseline. Baseline: 63/63 unfiltered (confirming).
- **Phase A** — end-to-end driver. New bench mode (name TBD; `m4tree` is taken by the step-1a
  recorder — use a distinct mode). Drive leaf×2 (distinct) → interior → native verify chain +
  the issue #24 hard assertion. `--lane b4|b2`. A cheap SAT test (small config) guards the driver
  logic without a 30 GB prove.
- **Phase B** — Σfee rider. Add the exposed root pv + the constraint-level sum over the routed
  fee slots; the native `merge_root`/driver recompute Σfee and hard-assert. Two negatives.
- **Phase C** — measurement (heavy, foreground, bare-metal, zero-swap, /usr/bin/time -l, twice).
- **Phase D** — PR (no merge). Optional 1c side road as a separate commit if time remains.

## Implementation landed (files)

- **Phase A** — `crates/qlab-bench/src/m4assembly.rs` (new module) + `main.rs` (`mod m4assembly;`
  + `m4assembly` mode arm with `--lane`). `run_m4assembly(power, lane)` proves leaf L →
  native-verify → drop → leaf R → native-verify → drop → interior prove → native-verify →
  **hard-assert** `consumer_root_ok` (issue #24) **and** `consumer_fee_ok` (棒 3-3). Reports
  per-segment wall time + fixed size + whole-tree wall. `--lane b4|b2`.
- **Phase B** — the Σfee rider, in `m4gate.rs` + `m4interior.rs`:
  - `m4interior::EPOCH_FEE_LIMBS = 4`, `const _` assert glued to `qlab_air::narrow::PV_FEE..PV_LEN`.
  - `num_public_values`: interior += `MERGE_ROOT_LIMBS + EPOCH_FEE_LIMBS`.
  - `build_interior_trace`: appends `Σfee[j] = opvs[n_opvs-4+j] + opvs[2·n_opvs-4+j]` (from the
    ASSEMBLED, already-`monty_rr`-scaled halves) after the merge root.
  - `eval` (棒 3-3, inside `if route`, after the root-squeeze bind): `meq[3] · (pv(sfee_base+j)
    − pv(feeL+j) − pv(feeR+j))`, deg 1. `feeL = n_opvs-4+j`, `feeR = 2·n_opvs-4+j`,
    `sfee_base = 2·n_opvs + MERGE_ROOT_LIMBS`.
  - Fee is the TAIL of each pv half (M3 fee is the PV tail → opvs tail → half tail).

## Tests
- `m4assembly::tests::{consumer_root_predicate_binds, consumer_fee_predicate_binds}` — cheap, no proving.
- `m4gate::tests::interior_epoch_fee` — positive: opvs tail == feeL+feeR, `check_constraints` SAT.
- `m4gate::tests::interior_neg_epoch_fee` — 3 probes: tamper exposed Σfee → UNSAT; tamper child
  fee source only → UNSAT; tamper feeL + Σfee CONSISTENTLY → still UNSAT (fee is child-bound via
  `WordBind::Pv`). The third is the meaningful "faked child fee" negative.
- Existing `interior_merge_native` opvs-length assertion updated (+`EPOCH_FEE_LIMBS`).

## Finding (Phase B gate, 2026-07-21): the rider inherits issue #24's binding boundary

The first A+B gate surfaced a real, design-consistent fact. In the interior, each child's
**inner PVs (including fee) are NOT independently constraint-bound to the child proof** — the
merge sponge absorbs the child opvs as *witness* (issue #24's exact gap). Consequence for the
rider: the circuit binds `Σfee = feeL + feeR` over the **carried** fee slots only; a *consistent*
tamper (a child's fee AND the exposed sum, +1 each) is **SAT at the circuit level**.

This is not a soundness hole — it is the same posture as issue #24, and the authenticity of the
carried fees is delivered the same way: the **consumer-side recompute from verified children**.
So the driver's `consumer_fee_ok` was strengthened to recompute the expected `Σfee` from the two
verified leaf opvs (`m4interior::epoch_fee_sum_expected`, `(feeL+feeR)·rr`), exactly parallel to
`consumer_root_ok` recomputing `merge_root`. Circuit-level negatives keep the two genuine ones
(tamper exposed Σfee / tamper a child fee source → UNSAT via the sum bind); the consistent-tamper
case is pinned as a **documented boundary test** (`interior_epoch_fee_boundary`, asserts SAT) so it
can never silently become a false soundness claim. Closing it in-circuit = issue #24's msh columns
(same fix, ~+2.4% cells) — out of scope here, correctly deferred to #24.

## Handoff state (update on interruption)
- Phase 0: DONE (recon PROCEED; baseline 63/63).
- Phase A + B: CODE COMPLETE. Cheap predicate tests green (67 tests total). Full unfiltered
  release acceptance gate RUNNING (validates the two heavy interior Σfee tests + deg ≤ 3 guard).
  Two commits queued (A, then B) once the gate is green; NOT yet committed.
- Phase C (measurement) + D (PR, no merge) pending.
