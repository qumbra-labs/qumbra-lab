# M-WHIR step 0 — zk/hiding-module assessment (read-only side deliverable)

> Reads Plonky3 0.6.2 `p3-whir/src/pcs/zk/` against
> [eprint 2026/391](https://eprint.iacr.org/2026/391) (Chiesa–Fenzi–Weissenberg,
> HVZK-WHIR). **No code was enabled or modified.** A privacy chain cannot ship a
> non-hiding PCS, so this module is a *hard* adoption gate (whir-reeval §3.3).
> This is a maturity read, not an audit.

## 1. Implementation completeness — substantially complete

The module is not a stub. `pcs/zk/` is ~5,158 lines (incl. tests) implementing
the full four-stage HVZK pipeline its own `mod.rs` documents:

| stage | construction (2026/391) | file |
|---|---|---|
| commit — interleaved ZK Reed-Solomon encoding | — | `committer.rs` (266) |
| fold — masked sumcheck batches | Construction 6.3 | `prover/mod.rs`, `prover/masks.rs` |
| reduce — HVZK code-switching rounds | Construction 9.7 | `code_switch.rs` (354) |
| finish — non-succinct masked base case | Construction 7.2 | `base_case/` (prover+verifier+tests) |

- `HidingWhirPcs` implements `MultilinearPcs<EF, Challenger>` with the **same**
  MMCS-generic + challenger bounds as the non-ZK adapter (so a Keccak MMCS fits
  it too — and the same uni-stark structural block applies; see
  `mwhir-step0-plan.md`).
- Config is validated, not assumed: `ZkConfigError` covers `MaskLengthTooSmall`,
  `MaskRateTooHigh`, `RandomnessExceedsSlack`, `MaskDomainExceedsTwoAdicity`,
  each with a unit test.
- No `todo!`/`unimplemented!`/`FIXME`/placeholder in non-test code; the only
  `panic!`/`debug_assert!` hits are a config-error test and prover sanity checks.
- **49 test annotations, 0 `#[ignore]`.**

## 2. Correspondence to the paper — explicit and traceable

Doc comments cite exact objects: the committed-sumcheck relation (Definition 5.8)
`⟨f, W⟩ + Σᵢ ⟨ξᵢ, uᵢ⟩ = target` is carried in the code's mask bookkeeping;
batching follows Construction 5.5. The module states its **deliberate deviations**
from the non-ZK pipeline, all sourced to 2026/391's round-by-round analysis:
- **no commitment-phase OOD samples** — replaced by list-size union bounds;
- per-round batching coefficients start at the first challenge power (carried
  claim keeps coefficient 1; each fresh constraint gets an independent coeff);
- **prefix variable order only**.

The four "what is revealed" claims (sumcheck wires → per-round masks; OOD → private
zero-evader pad; query openings → encoding randomness budget; final message →
fresh one-time mask) each map to code paths in `prover/masks.rs` +
`base_case/prover.rs`. Correspondence is good *at the level of structure and
naming*; verifying the constants/bounds match the paper's theorems is an audit
task, out of scope here.

## 3. Visible gaps (what a privacy-chain integrator must weigh)

1. **Hiding path is single-polynomial only.** The hiding adapter's
   `Witness = Poly<F>` and `OpeningProtocol = Vec<Point<EF>>` — there is **no
   batched-`Table`/`Layout` path**, unlike the non-ZK `WhirProver` (which batches
   many columns via `Layout`). A STARK trace is many columns; committing it hiding
   would need flattening into one `Poly`, which on KoalaBear hits the 2-adicity-24
   domain wall (see `mwhir-soundcalc.md`). So the hiding module as shipped does
   not obviously cover a wide-trace commitment.
2. **ZK property is under-tested relative to soundness.** The 14+ negative tests
   (`rejects_wrong_eval`, `rejects_tampered_ood_answer`, `rejects_truncated_*`,
   `rejects_tampered_pow_witness`, …) exercise **soundness** thoroughly. The
   **hiding** side has essentially one direct test —
   `base_case_reveals_are_one_time_padded` — and **no full-transcript HVZK
   simulator test** (the property that the entire proof is simulatable without the
   witness). For a privacy chain the hiding property is the load-bearing one; here
   it is the less-tested one.
3. **Non-succinct base case** (Construction 7.2, by design) — a proof-size cost on
   top of the wide-trace penalty already found for the non-ZK path.
4. **Accounting tool does not cover it.** `ethereum/soundcalc` (rev 809896fb)
   models the **non-ZK** WHIR only; the ZK variant's modified round-by-round
   accounting (no commit-OOD, mask/code-switch overhead) is **not** verifiable
   with the tool we used for `mwhir-soundcalc.md`. Parameter derivation for the
   *hiding* variant currently has no independent checker.
5. **HVZK, non-interactive via Fiat–Shamir** — acceptable and matches Qumbra's
   current posture, but the FS transform of the ZK claim needs its own review.
6. **RNG is load-bearing and caller-supplied.** ZK holds only if `rng` is a
   CSPRNG; the adapter documents that a predictable stream lets an observer strip
   every mask and recover the witness. Tests seed a deterministic generator on
   purpose — correct for tests, a foot-gun for integrators.

## 4. Distance from review-grade — real engineering maturity, not yet review-grade

**For:** structured, paper-mapped, config-validated, soundness-tested across
regimes (UDR + JBR) with completeness proptests and a dozen-plus tamper negatives;
no stubs; compiles and (per the crate's own tests) round-trips.

**Against, for a privacy chain's hard ZK gate:** (a) no full HVZK/simulator test —
the hiding property itself is barely tested; (b) no external audit and **no
production use found** (whir-reeval §1.4); (c) the module is weeks old and
"still being reworked as of June 2026" — the rbr accounting that swaps OOD for
list-size union bounds is new and unbattled; (d) single-poly-only hiding adapter;
(e) the parameter accounting for the ZK variant is not covered by any independent
tool.

**Bottom line (factual, no verdict):** the HVZK-WHIR module is a serious,
substantially-complete implementation with strong *soundness* test coverage — well
beyond a prototype — but it is **not review-grade for shipping as a privacy
chain's only hiding PCS**: its *zero-knowledge* property lacks a simulator-level
test, it has no audit or production track record, its hiding adapter is
single-polynomial, and its parameters can't yet be independently checked. This is
consistent with whir-reeval §3.3 calling the zk gate "the least mature piece of
the stack." Enabling or modifying it was explicitly out of scope for step 0.
