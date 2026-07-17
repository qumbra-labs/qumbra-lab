# SPEC: M4 step 0b(ii) increment 4 — finish the verifier gate rectangle (gate exit)

**For the implementing session.** This branch (`claude/m4-0bii-inc4`) is a relay: two prior sessions landed Stage 1 and Stage 2 and were terminated by usage limits. This spec is self-contained — everything you need is in this repo + the two stage commits. The main coordinating session will verify your work afterward (independent bench reproduction, test rerun, PR); your job is implementation + honest reporting.

## 0. Orientation — read in this order, before writing any code

1. `CLAUDE.md` (repo root) — project context, Milestones (the "increments 2+3 DONE" and "NEXT — increment 4" bullets are the parent spec of this doc), Bench discipline, Working conventions.
2. `git log --oneline origin/main..HEAD` and `git show --stat` each stage commit:
   - `c553458` **Stage 1**: `crates/qlab-bench/src/m4gaterec.rs` (~1,520 lines) — a *verification recorder*: runs the real uni-stark verification of a real M3 consensus proof and records the full transcript/schedule (every keccak absorb, every challenger draw, every opened value), cross-checked against native verification. This is your witness source and your ground truth.
   - `482e873` + `b822be1` **Stage 2**: `crates/qlab-bench/src/m4gate.rs` — the gate-rectangle module: column map, query program, lane plan, and a **full witness simulator that is green on the real proof**. Key discovery recorded in the commit message: the transcript is Monty-word encoded end-to-end (R-homogeneous pipeline) — the rectangle's arithmetic works directly on Monty representatives, no conversions. Rectangle shape: **3,532 cols × (2,382 lane perms)**.
3. `crates/qlab-bench/src/m4route.rs` (~950 lines, merged PR #16) — the routing + FS gadgets you will reuse/extend: step-flag-muxed same-row equality routing (overwrite-mode sponge + 24-row preimage replication makes this sound), FS byte-packing (2 rows/draw, reject-redraw comparator `accept = 1 − t7·nz`, all deg ≤ 3), native cross-check test pattern.
4. `crates/qlab-air/src/narrow.rs` — the M3 bucket's binding machinery you will mirror: **program ring** (phase-packed, 4 slots × 4 bits/limb), **equality banks** (pos/neg/close gates), **epoch one-shot** (kills program replay in padding). These are the proven patterns for schedule binding.
5. `docs/m4-verifier-circuit-layout.md` — subsystems 5 (batched ext-inv) and 6 (public surface); the acceptance section quotes aggregation-rung1 §6.
6. `docs/m4route-step0bii-run1.md` — the two prover-performance lessons (see §5 below) and the inc-2/3 caveats.

A previous session's in-flight edit was discarded: an unverified swap of the constraint-check helper in the `gate_rectangle_satisfies` test. **Run that test first** and proceed from what it actually reports — do not assume it passes or fails.

## 1. Goal

Turn the Stage-2 rectangle (witness green, constraints incomplete) into a **fully constrained AIR** that (a) accepts the real M3 proof's transcript as its only satisfying assignment class, and (b) is unsatisfiable under the four gate-exit tamperings. This is the exit gate of M4 step 0b(ii); after it, the tree prototype (step 1) starts.

## 2. Work items

### 2.1 Complete the constraint set (the bulk)
Every column region of the 3,532-col map must be constrained; no free witness regions except genuine witness (opened values, witnessed inverses). Specifically:
- **Lane region**: stock keccak AIR constraints via the LaneBuilder offset adapter (proven in `m4skel.rs`); lane scheduling bound to the program ring — the prover must not choose which perms absorb what.
- **Bank regions** (ext-mul, ext-add): existing bank constraints (from `m4anchor.rs` lineage) + **schedule binding**: which bank row consumes which routed operand is program-determined, not witness-determined.
- **Routing/FS gates**: inc 2+3 built the gadgets with gate columns as free witness (`g_inj*`, `fs_gate`, `chain_gate`). Bind them to the program ring / periodic schedule. Precedents: M3 program ring + epoch one-shot in `narrow.rs`.
- **Query program**: Stage 2's query program (which FRI query touches which Merkle path / fold round) must be constraint-derived from the sampled challenge bits, not witnessed. This closes the loop: challenges (FS gadget) → query indices (sample_bits, §2.2) → opened-value routing.
- Degree budget: **all constraints deg ≤ 3** (house rule since M1.5b; the quotient width is sized for it).

### 2.2 `sample_bits`
FRI query indices use the challenger's `sample_bits` path, not full field draws. Read pinned `p3-challenger` 0.6.1 for exact semantics (LE bytes from digest end, mask to `log2(domain)` bits, **no rejection**). Constrain consistently with the inc-3 gadget (same digest-chaining discipline). The inc-3 native cross-check test pattern (`fs_matches_native_challenger`) is the model — add the sample_bits analogue.

### 2.3 Ext-challenge assembly
4 accepted base-field draws → one 4-limb extension tuple emitted to the banks (KoalaBear deg-4 binomial extension; limb order must match `p3_field`'s serialization — cross-check natively like inc 3 did). This completes the layout doc's "route as 4-limb tuples throughout".

### 2.4 Batched ext-inv
60 inversions per verified proof via ONE product chain in the mul bank (~180 bank rows) + a single witnessed inverse checked by one mul row (`chain_product · witness_inv = 1`). Layout doc subsystem 5.

### 2.5 Public surface (the tree-node interface)
Inner proof commitments + inner public values enter as **outer public values**; the rectangle exposes upward a running digest binding (inner digest set + verified flag). Keep the interface minimal and documented in the module header — M4 step 1 (tree prototype) consumes exactly this.

### 2.6 Canonicity disposition
Inc 2 deferred the routed-word v vs v+p byte-alias to "killed transitively by digest binding." Now that digest binding exists: **verify that claim mechanically** (construct the would-be alias and show a constraint breaks) or add the missing canonicity constraint. State the disposition explicitly in your report — this is a soundness item, not bookkeeping.

### 2.7 Col accounting
Stage 2's rectangle is 3,532 cols vs the 2,685 post-inc-3 plan (+847). In the report, break the growth down by region (query-program cols? sample_bits bit cols? ext assembly? padding?) — the design repo's measured-update needs this table. Growth is acceptable; unexplained growth is not.

## 3. Tests (the acceptance bar — aggregation-rung1 §6)

- **Positive**: the rectangle accepts the real M3 proof's recorded transcript end-to-end (constraint check over the full trace; a prove/verify roundtrip at one config).
- **Four negatives, individually reported, each UNSATISFIABLE** (constraint violation, not wrong-output):
  1. tampered opening (flip a byte in one opened value)
  2. wrong root (substitute a different Merkle root / inner commitment)
  3. wrong challenge (force a challenge ≠ the FS-derived one)
  4. bad fold (corrupt one FRI fold relation)
- All existing tests keep passing (14 from inc 2+3, plus Stage 1/2's own).
- Negative tests must fail **because of the new bindings** — if a negative passes with gate columns still free, the binding is incomplete.

## 4. Bench + records

- Configs: b4/q40/g20/fp16/a16 and b16/q20/g20/fp16/a16 (the two house lane configs).
- Report: cols total, rows, prove ms (best-of-3), peak RSS (via the existing `--only` RSS path), fixed-width KB.
- TWO fresh-process runs; write `docs/m4gate-step0bii-run1.md` and `run2.md` (follow the format of `docs/m4route-step0bii-run*.md`).
- Context anchors: inc-1 skeleton was b4 ≈ 476–561 ms / 3.58 GB / 597.9 KB; inc-2+3 b4 ≈ 455–497 ms / 3.61 GB / 603.1 KB. The full rectangle is bigger (3,532 cols, 2,382 perms) — expect growth; report it against these anchors.

## 5. Engineering constraints (hard-won, do not relearn)

1. **Narrow Expr collect**: full-width expression collection in `eval` runs per LDE point and cost +70% prove in inc 1 — collect only needed columns.
2. **Up-front LDE capacity**: trace buffers must reserve LDE capacity at allocation; late realloc tripled RSS in inc 1.
3. **No repo-wide `cargo fmt`**: the base rev has known fmt drift under rustfmt 1.9.0; format only files you touch (a prior session's whole-workspace fmt was discarded as noise).
4. **Monty-word homogeneity** (Stage 2's discovery): the transcript pipeline is R-homogeneous — do not insert to/from-Monty conversions; work on representatives.
5. All security-relevant configs assert ≥100 conjectured bits at runtime (helper exists).

## 6. Process discipline

- **Commit in meaningful stages** with descriptive messages — this branch is a relay and sessions die; every committed stage survives. Do NOT push; do not touch the design repo (`~/develop/qumbra/qumbra-design`) — the coordinating session owns that.
- `cargo check` green at every commit; touched files fmt-clean.
- **Honesty over completeness**: PARTIAL with a precise remainder beats a soft DONE. Do not weaken a negative test to make it pass. If an item is blocked by a 0.6.1 API limitation, document the blocker with the exact API surface consulted.

## 7. Final report format (for the coordinating session)

```
STATUS: DONE | PARTIAL (remainder: …) | BLOCKED (blocker: …)
COMMITS: <hash> <msg> (one line each, all stages)
BENCH: both run tables verbatim
COLS: 3,532 → <final>, growth table by region
NEGATIVES: 1) tampered opening: PASS/FAIL(reason) 2) wrong root: … 3) wrong challenge: … 4) bad fold: …
CANONICITY: disposition of v/v+p alias (verified-transitively | constraint-added), with the mechanism
TESTS: <n>/<n> release
FILES: wc -l of changed files
```

The coordinating session will then: independently rerun tests + bench, review the diff, open/merge the PR, sync the design repo (ROADMAP + measured updates), and kick off M4 step 1 (tree prototype).
