# Issue #78: bind consumed words to the sponge

[中文](i78-word-binding-zh.md). Scope: finding 4 of [issue #78](https://github.com/qumbra-labs/qumbra-lab/issues/78), following the SCR carry repair in [PR #752](https://github.com/qumbra-labs/qumbra-lab/pull/752). This is a prerequisite of [issue #750](https://github.com/qumbra-labs/qumbra-lab/issues/750).

The M4 arithmetic pipeline consumes `W0C/W1C`, including both halves of values
assembled through ASM. Previously the word-recovery constraints only applied on
F0 permutations. The duplicate chain, final-polynomial flush and query leaf
absorbs therefore lacked this direct connection to their sponge inputs. A lone
word mutation could already fail downstream arithmetic constraints; that failure
did not demonstrate a sponge binding.

## Binding and cost

Reuse the existing direct and bitwise-XOR recovery constraints with these gates:

| Permutation | Recovery |
|---|---|
| First block of every observation flush | Direct preimage rate |
| Later observation blocks, except original F2 | Preimage XOR previous output rate |
| Refill | Direct preimage rate |
| First duplicate block | Direct preimage rate |
| Later duplicate blocks | Preimage XOR previous output rate |
| Query leaf absorb roles 1–5, including continuation blocks | Direct preimage rate (overwrite sponge) |
| Original F2 interior, query arithmetic/path, padding, merge | No routed-word binding; these cells are not consumed there |

The original F2 interior has no filled routed words. Its duplicate chain supplies
the consumed openings, and the existing digest comparison binds that chain to the
original observation. Neither that comparison nor the witness fill changes.

Let `O0` sum first-observation-block selectors, `OX` sum later-observation-block
selectors excluding F2, and `QA` sum query absorb-role selectors. The existing
materialization is constrained to `xsel = phd*(1-cmpc) + OX`. Set:

```text
gxor = xsel
gdir = O0 + refsel + phd - xsel + OX + QA
```

Thus the duplicate-first-block term is algebraically `phd*cmpc`, expressed through
linear columns. Multiplying it by the degree-2 row mux stays within the degree-3
budget. Source-derived cost **[P]**: **0 new columns**, **0 new constraints**;
the same **140** recovery constraints cover the additional permutation classes.
No proving-time or memory improvement is claimed.

## Discriminating checks

The existing narrow, wide and distinct two-child SAT tests reuse their already
allocated traces for component checks. For every child permutation, the recovery
gates must match an independent classification of the recorder's schedule. Each
observation/direct/XOR/query-role-and-batch class supplies representative rows.
Checks cover first/last rate rows, first/last non-rate rows, both word columns,
and boolean-preserving mutations of preimage/output decomposition bits.

A test-only F0-gated reference evaluates the same recovery equations. Outside F0,
word mutations pass that old component and fail the expanded component when the
word is consumed. This isolates the repaired relation from downstream accumulator
counter-pressure. It is a component-level regression, not a complete forged-proof
construction. Padding and merge selectors are checked to remain inactive. The
existing symbolic degree guard also pins the recovery component's constraint count.

## Validation and limits

Local `cargo check --workspace --all-targets --locked` and
`cargo clippy -p qlab-bench --all-targets --locked` passed; Clippy has existing
repository warnings. No local test, proof or benchmark was run. Complete Graviton
acceptance is pending. Existing test functions gain assertions; the expected test
count remains the prerequisite branch's 2721 passed **[P, pending CI]**.

This changes the experimental M4 verifier AIR. Transaction AIRs, consensus
parameters, committed transaction fixtures, lockfile and deployment are unchanged.
Generated M4 proofs must use the strengthened AIR. Unverified, most likely to fail
first: expanded recovery compatibility with honest wide/interior traces, pending
CI; the new component rejection checks, pending CI; target-rig cost. Full
AIR/quotient verification and hiding-leaf integration remain missing. This does
not close issue #78, establish full recursive soundness or pass F2's memory gate.
