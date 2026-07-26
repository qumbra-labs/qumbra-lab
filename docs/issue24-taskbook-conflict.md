# Issue #24 task-book conflict report (builder, 2026-07-26)

**Status: STOPPED BEFORE IMPLEMENTING. No scope-item edits made.** This document is
the evidence for a redirect request back to the coordinator.

Branch `claude/i24-merge-binding`, worktree `../qumbra-lab-i24`, base `5a24e49` (main).

## The conflict in one line

The coordinator's task-book comment (2026-07-25T16:23, "Coordinator decision +
task-book — closing #24") adopts path 2 and **declines path 1 (in-circuit `msh`
binding) as an unaffordable contingency to be *measured only*** — but **path 1 was
implemented, coordinator-accepted, and merged into `main` four days earlier**
(PR #30, commit `a9e2fc6`, 2026-07-22), and is live in the interior AIR today.

## Evidence

### 1. Path 1 is in `main` and active

- `crates/qlab-bench/src/m4gate.rs:2469` — block headed
  `Issue #24 (D1): merge preimage → pv(opvs) MESSAGE BINDING`. For each child
  sponge perm `p`, binds the absorbed rate block (34 values × two u16 preimage
  limbs) to the child's inner PV at the fixed index, gated by `msh[p]·sf(0)`:
  `gate · (recompose·rr − pv(half + OPV_INNER + 34·block + j)) == 0`, with the
  padding positions pinned to the pad10*1 constants.
- The in-code comment states the effect explicitly: this upgrades the root bind
  "from computational — hitting pv(root) ⇒ honest inputs BY KECCAK PREIMAGE
  RESISTANCE, the PR #23/#25 caveat — to an UNCONDITIONAL constraint-level bind".
- `m4gate.rs:1428-1432` — layout: `msh = dlr + 16`, `mrot = msh + merge_perms()`.
- `m4gate.rs:2415-2467` — the D0 ring is **positively pinned**: `assert_bool` per
  slot, `Σ msh == mreg`, start-edge anchor to slot 0, forward rotation via
  materialized `mrot`, `when_last_row().assert_one(msh + (nm−1))`. A dropped ring
  is UNSAT, not a silent binding vanish.
- Not feature-gated. `merge_perms()` returns 0 only for shapes without a merge
  lane; the interior (`GateShape::wide()`) has one.

### 2. The prior coordinator comment on this same issue already said so

Issue #24 comment 2026-07-21T17:24 (coordinator):

> **D0–D2 merged (PR #30, coordinator-accepted 2026-07-22): bindings 1 (merge
> preimage) and 2 (Σfee inputs) are CLOSED at constraint level** — msh one-hot ring
> positively pinned (+54 wide-only cols ≪ +91 budget) […] interior 19.72 GB (under
> budget); 79/79. **Interior bindings now UNBLOCK ≥3-level trees. Remaining: D3
> (leaf F0 digest input binding).**

`CLAUDE.md:58` records the same. `docs/issue24-findings.md` is the builder's D0–D2
findings + the D3 spec.

### 3. The task-book's cost premise is a base error, and the base already includes `msh`

The task-book's ground #1 reasons: the issue prices path 1 at ~+0.7 GB on a
measured **30.42 GB**; the b4-fallback re-measure put an interior configuration at
**31.21 GB**; +0.7 GB on *that* → ~31.9 GB, margin gone.

Provenance of each number (all traced in-repo):

| number | what it is | includes `msh`? |
|---|---|---|
| **30.42 GB** | two-child **b4/q40**, PR #23 stage-3 (`docs/m4interior-stage3-run{1,2}.md`) | **no** — pre-PR #30, pre-B″ |
| 20.53 GB | two-child **b2/q80**, same era | **no** |
| **19.72 GB** | two-child **b2/q80/g22** at PR #30 (`docs/issue24-findings.md:59`) | **yes** |
| 20.2–20.9 / 22.5 GB | two-child **b2/q86** post-B″ (PR #47) | **yes** |
| **31.21 GB** | **b4-fallback at q43**, re-measured 2026-07-24, design PR #50 (`CLAUDE.md:66`) | **yes** |

So the 31.21 GB figure the decision is defending **already contains** the `msh`
columns. The +0.7 GB cannot land on it a second time — it is already paid. The
30.42 → 31.21 delta (+0.79 GB) spans *two* changes, the B″ query bump q40→q43 and
`msh`, and attributing all of it to `msh` double-counts.

The estimate was also conservative on width: the issue budgeted **+91 wide-only
columns**; the landed implementation uses **+54** (`msh` = `merge_perms()` = 53,
`mrot` = 1). `merge_perms() = 2·(n_pvs·4/136 + 1) + 1` with `n_pvs = 852`
(`m4gate.rs:6160`) → `2·26 + 1 = 53`; unchanged post-B″.

### 4. The self-reversal condition is already met by landed evidence

The task-book states: *if path 1's true cost lands inside the 32 GB envelope with
**≥ 5 % margin** on the current interior configuration, path 1 becomes the better
answer and this decision is reopened.*

On the **decided** interior lane (b2/q86 — `m4interior.rs:222`, "the DECIDED
interior lane"), the measured post-`msh` footprint is **20.2–22.5 GB** against
32 GB → **~30–37 % margin**, with `msh` already in it. The condition is satisfied
by measurements that already exist, not by a contingency measurement.

### 5. Scope items 2 and 3 are already implemented

- **Scope 2 (structural consumer check at every seam):** the `m4assembly` driver
  hard-asserts both invariants on the verified children, not optionally
  (`m4assembly.rs:153-161`):
  `consumer_root_ok(...)` — "issue #24 consumer check FAILED: interior root pv !=
  keccak-merge(opvsL, opvsR)" — and `consumer_fee_ok(...)`. Landed in PR #25.
- **Scope 3 (negative test: jointly-chosen inconsistent `opvs`/`root` rejected by
  the consumer path):** `consumer_root_predicate_binds` (`m4assembly.rs:199`)
  — honest root passes; **every** root limb tampered in turn rejects; mismatched
  child opvs rejects. Its doc comment names it as the predicate the driver
  hard-asserts. Sibling `consumer_fee_predicate_binds` does the same for Σfee.
- At *circuit* level the same attack is additionally unprovable:
  `interior_neg_merge_msg` (`m4gate.rs`) tampers a child-L / child-R inner PV in
  the exposed opvs leaving the keccak trace untouched — "Was SAT (SAT-MISS) before
  D1; must be UNSAT now" — plus `interior_neg_msh_ring` (ring absence / end-anchor
  drop / spurious one-hot / `mrot` tamper → all UNSAT).

### 6. Scope item 1's proposed wording would put a false claim into the spec

The task-book asks `aggregation-rung1.md` §2 to gain, as a **binding** invariant:

> […] an interior proof that has not been so checked **establishes nothing about
> which children it aggregated**.

With D1 landed this is **factually wrong**. The interior AIR now binds every child
inner PV into the merge sponge preimage unconditionally, so an interior proof that
verifies *does* establish which children it aggregated, with no consumer check and
no appeal to preimage resistance. Landing that sentence would understate the
prototype's guarantee inside the rung-1 statement — the opposite of the honesty
goal in the decision's own ground #3.

## What is actually still open on #24

**D3 — leaf F0 digest input binding** (the third binding from the 2026-07-21
consolidation comment). Full spec in `docs/issue24-findings.md`: F0 is XOR-mode
(not overwrite), so recovering the absorbed message needs a per-bit XOR against the
previous perm's output; selector reuses the existing `shsel` flush automaton (no new
ring); `f0dig` mirrors `f2dig`; and exposing it **cascades the leaf public surface**
(`N_OPVS` → `GATE_WIDTH` → interior inner-PV count → `merge_perms()` → `msh` width
→ opvs layout), which is the one place the narrow-byte-identical invariant must
break. Gates any leaf-digest exposure. The task-book does not mention D3.

Note D3 touches the leaf public-value layout by construction, which is adjacent to
the task-book's stop-point clause ("if closing the binding turns out to require
changing the interior AIR's public-value layout … stop and report"). Flagging now
rather than after starting.

## Requested redirect (coordinator's call)

1. **Confirm the decision is moot as written** — path 1 is shipped; there is nothing
   to decline and no contingency to measure.
2. **Re-word scope item 1.** If §2 should still carry a consumer obligation, it must
   be stated as defense-in-depth over an already-unconditional in-circuit binding,
   not as the thing that makes the interior meaningful. Proposed wording is in the
   report to the coordinator; it is not landed here (design repo is yours).
3. **Decide what this baton actually is:** (a) close #24's remaining D3, (b) a
   documentation-only pass reconciling issue #24's stale body with the landed state,
   or (c) something else. D3 is a substantially larger, consensus-critical change
   than the task-book scoped.

No heavy runs were started: `m4gate` / b4 interior bench and the full
`--release --workspace` suite were **not** invoked (4-node docker soak holding the
rig). All findings above are static — code, git history, and already-recorded
measurements.
