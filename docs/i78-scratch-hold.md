# Issue #78: carry scratch values between their writes

[中文](i78-scratch-hold-zh.md). Scope: finding 2 of [issue #78](https://github.com/qumbra-labs/qumbra-lab/issues/78), a prerequisite of [issue #750](https://github.com/qumbra-labs/qumbra-lab/issues/750).

The existing `i78_finding2_scr_no_hold` test deliberately asserted SAT after changing
SCR0 between an M_FHI write and its next read. It recorded a missing carry, not a
successful full-proof forgery. The current change inverts that exact witness into
`gate_neg_scr_no_hold` and adds cross-permutation and wide/interior coverage.

## Constraint change

For each scratch slot, construct its write selector from the already-bound selectors:

- Leaf folds: `GF[round] * VC[2 * slot + 1]`, for each round that writes the slot.
- Higher folds: the corresponding materialized `FHG` gate, except the final pair,
  whose target is RUNEV rather than SCR.
- Reduced opening: `M_RO * step[row]`, with SCR0..4 written on rows 0, 1, 2, 4, 6.

The new transition constraint is `(1 - writes[slot]) * (next_scr - scr) == 0`.
The existing write constraints remain. The phase/query routing makes the producer
selectors disjoint; a slot is either written or carried. The complement therefore
also covers gaps between permutations, child boundaries, padding and merge rows.
The existing witness generator already inherits SCR into the second child and holds
the final child's registers in the tail, so no fill changes or boundary exemptions
are required.

Source-derived cost **[P]**: 8 extension slots × 4 limbs = **32 constraints**, **0 added
columns**, maximum added constraint degree **3**. These are code-derived counts,
not measured proving time or memory. Existing degree and width/height regression
guards remain in the suite. Transaction AIRs, consensus parameters and committed
transaction fixtures are untouched; this changes the experimental M4 verifier AIR,
so its generated test proofs are recomputed under the strengthened constraints.

## Tests and remaining work

- Invert the existing narrow free-interval witness; retain the RUNEV negative control.
- Add a SCR7 mutation across a permutation boundary, away from a fold read.
- Add the former free-interval mutation to the existing wide negative test and
  separately to each lane of the distinct two-child interior negative test.
- Reuse the existing honest narrow/wide/interior satisfaction tests and symbolic
  degree guard. Mutations recompute derived auxiliary columns before checking.

No local tests, proving or measurement were run. Local workspace compilation passed;
the PR's complete Graviton acceptance run must establish actual test success.

Unverified, most likely to fail first: honest wide/interior boundary compatibility
pending CI; the new rejection cases pending CI; performance on the target rig.
Finding 4 (sponge binding of W0C/W1C) remains open. Full AIR/quotient verification is
still missing from the prototype. This change does not close issue #78, establish
full recursive soundness, or pass F2's memory gate.
