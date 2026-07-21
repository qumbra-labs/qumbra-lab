# M-WHIR step 0 — plan, findings & stop-point log (EXPERIMENT BRANCH)

> Branch `claude/mwhir-step0`, isolated from `main`. Main stays frozen on the
> fully-measured Plonky3 0.6.1 record; this branch is on 0.6.2 and **never
> merges before an adoption decision**. This is a *measurement* baton — the
> verdict belongs to the coordinator; nothing here adopts or decides.
>
> Spec: qumbra-design `whir-reevaluation-2026-07.md` §5. Accounting conventions:
> `fri-soundness-accounting-2026-07.md`. Bench discipline: qumbra-lab `CLAUDE.md`.

## Task ledger

| # | Task | Status |
|---|---|---|
| 1 | Stack upgrade this branch → Plonky3 0.6.2; full `cargo test --release -p qlab-bench` green | ✅ DONE — **68/68 passed** on 0.6.2 (STOP-POINT A clean) |
| 2 | WHIR bench mode (`mwhir`): prove real M3 statement via p3-whir PCS + Keccak MMCS | 🛑 **BLOCKED — STOP-POINT B (structural)** |
| 3 | Parameter derivation via ethereum/soundcalc, two points; confirm/refute ~80-bit degree-4 cap | ✅ DONE — `docs/mwhir-soundcalc.md`; ~80-bit cap **CONFIRMED** |
| SD | zk/hiding-module assessment vs eprint 2026/391 (read-only) | ✅ DONE — `docs/mwhir-zk-assessment.md` |
| 4 | Measurement, both points, twice, `/usr/bin/time -l` | ⚠ no WHIR numbers measurable (task 2 blocked); FRI baseline + soundcalc derivation on record |

## Stop-point log

### STOP-POINT A — NOT triggered ✅
The 0.6.1 → 0.6.2 upgrade required **zero** rewrites of consensus-circuit code.
`cargo check -p qlab-bench --tests` compiles clean on 0.6.2 (only the pre-existing
dead-code warnings) — no import changes, no signature changes to qlab-air / the
narrow-Keccak AIR / the bucket builder / the m4* verifier code. The experiment
branch does not drift from main's circuit semantics. Full release regression suite
result recorded below when it completes.

### STOP-POINT B — TRIGGERED, gap is STRUCTURAL 🛑
**"Keccak-instantiated uni-stark WHIR" is not constructible in Plonky3 0.6.2 by
wiring.** The block is **not** the Keccak MMCS (that part is fine — see below); it
is an architecture mismatch at the uni-stark ↔ PCS boundary.

Evidence (all from the resolved 0.6.2 registry source):

1. **p3-commit 0.6.2 has two disjoint PCS traits.**
   - `p3_commit::Pcs<Challenge, Challenger>` (`src/pcs/univariate.rs`) — the
     *univariate* scheme: `type Domain: PolynomialSpace`, commits row-major
     matrices as univariate polys over a coset LDE, opens at out-of-domain points.
     This is what FRI (`TwoAdicFriPcs`) implements.
   - `p3_commit::MultilinearPcs<Challenge, Challenger>` (`src/pcs/multilinear.rs`)
     — commits a `Witness` of multilinear polynomials over the Boolean hypercube,
     opens via an `OpeningProtocol` (sumcheck). **No `Domain`.**

2. **WHIR implements only `MultilinearPcs`.** `p3-whir/src/pcs/adapter.rs`:
   `impl<..> MultilinearPcs<EF, Challenger> for WhirProver<EF, F, Dft, MT, Challenger, L>`.
   Grep for a univariate `impl p3_commit::Pcs` for any WHIR type: **none exists**
   (the only two `impl … Pcs<` hits in the crate are both `MultilinearPcs`, in
   `pcs/adapter.rs` and `pcs/zk/adapter.rs`).

3. **uni-stark 0.6.2 is hardwired to the univariate `Pcs`.**
   `p3-uni-stark/src/config.rs`: `StarkGenericConfig::Pcs: Pcs<Self::Challenge,
   Self::Challenger>` and `Val<SC> = <Domain<SC> as PolynomialSpace>::Val`. There
   is no multilinear code path in `prove`/`verify`.

4. **No bridge crate exists in the 0.6.2 tree.** Nothing in the resolved graph
   consumes `MultilinearPcs` except p3-whir itself and p3-commit; p3-whir has no
   reverse dependents. There is **no multilinear/sumcheck STARK frontend** that
   takes a `p3_air::Air` and proves it over WHIR. (Spartan-WHIR / SP1-style
   provers that DO pair WHIR with a circuit are separate, non-Plonky3 stacks.)

**Consequence.** Our M3 statement is a `p3_air::Air` (`NarrowKeccakAir` + the
bucket builder), proven today by `p3_uni_stark::prove` over the univariate FRI
PCS. To prove *that same AIR* through WHIR you would have to author a complete
multilinear/sumcheck STARK prover (trace-as-multilinear, sumcheck constraint
reduction, next-row handling, public-value binding) wrapping qlab-air — a new
proof system, not a PCS swap. That is:
  - **far beyond the "MINIMAL local patch" allowance** in STOP-POINT B;
  - **not "semantics untouched / same as our FRI"** — it changes *how* the
    statement is proven at the deepest level;
  - **far beyond step 0's ~6–10 session-hour envelope.**

Per the pre-registered protocol ("if the gap is structural, stop and report"),
building is halted here. Tasks 3 (parameter derivation) and SD (zk assessment)
proceed because they do not depend on a runnable p3 WHIR-over-AIR prover.

### STOP-POINT C — NOT triggered ✅
p3 0.6.2 ships a ready degree-5 KoalaBear extension:
`QuinticTrinomialExtensionField<KoalaBear>` (irreducible `X^5 + X^2 - 1`,
|EF| = p⁵ ≈ 2^154.6, 2-adicity 24) — exactly the PSE precedent. `KoalaBearParameters`
impls `TrinomialQuinticData`. **No field extension needed to be implemented.** So
point (ii)'s degree-5 parameters were derived directly (soundcalc), not left on
paper for a missing field. (The measurement of point (ii) is still blocked — but by
STOP-POINT B, not by any field gap.)

**What the task's hypothesis got right.** §5 / the baton predicted "WhirProver:
MT: Mmcs<F> + Challenger: FieldChallenger + GrindingChallenger + CanObserve …
should take a Keccak MerkleTreeMmcs + SerializingChallenger32." That is accurate
at the *PCS* level — `WhirProver<EF, F, Dft, MT, Challenger, L>` is MMCS-generic
(`MT: Mmcs<F>`), so a Keccak `MerkleTreeMmcs` fits, and the challenger bounds
(`FieldChallenger<F> + GrindingChallenger<Witness=F> + CanSampleUniformBits<F> +
CanObserve<Commitment>`) are satisfiable. The gap the baton did not anticipate is
one level up: p3-whir is a **multilinear** PCS and Plonky3 0.6.2 ships **no
uni-stark (univariate) adapter for it and no multilinear-AIR STARK**. The design
doc's own note — "zero in-tree Keccak WHIR example, test, or benchmark (absence,
checked)" — is explained by this: the in-tree WHIR usage is bare-`MultilinearPcs`
on a raw `Poly`/`Table` (see `p3-whir/examples/whir.rs`, `benches/whir_pcs.rs`,
`src/pcs/tests.rs`), never through a STARK.

## What IS on record from this baton
- The 0.6.2 upgrade is mechanical (STOP-POINT A clean) — a real datum for any
  future adoption: the stack re-pin is free of circuit-semantic risk.
- Parameter derivation (task 3) and the ~80-bit degree-4 cap check — see
  `docs/mwhir-soundcalc.md`.
- The FRI consensus baseline for the comparison table (PR #26 re-bench):
  b16/q20/g22 = 139,721 B / ~1.8 s / ~11.8 GB footprint.
- zk/hiding-module assessment — see the PR body / `docs/mwhir-zk-assessment.md`.

## Handoff note (if interrupted)
The structural block (task 2) is the headline. Anyone resuming should NOT try to
force a uni-stark↔WHIR wiring — it cannot exist in 0.6.2. A real WHIR calibration
for Qumbra requires either (a) upstream shipping a multilinear-AIR STARK over
`MultilinearPcs`, or (b) Qumbra authoring one — both are their own milestones,
not step-0 work. Everything else in the ledger is independent of that.
