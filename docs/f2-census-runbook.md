# F2 native census: coordinator runbook

[中文](f2-census-runbook-zh.md). Governing record: [issue #750](https://github.com/qumbra-labs/qumbra-lab/issues/750).

Larry approved the stage-zero recommendation on 2026-09-26: retain the hiding transaction
AIRs at degree 4; develop non-hiding outer aggregation over public proofs/public data;
include full verifier and binding work before calling the aggregation gate complete;
prefer the b2 interior lane. Use **32,000,000,000 bytes** as the conservative working
envelope until the legacy GB/GiB ambiguity is resolved. The larger rig is a measurement
environment, not evidence that the production envelope has changed.

This change provides the first instruments: `f2fixture`, `f2census`, and `f2price`.
It does **not** provide `f2gate` or `f2interior`, lower a complete recursive verifier,
resolve issue #78, or claim a memory pass. The symbolic report names work still unpriced.
Complete that layout before any aggregation trace allocation.

## Run only on the coordinator's rig

Never run tests, fixture proving, or benchmarks on the developer machine. Local
`cargo check --workspace --all-targets --locked` is allowed. The acceptance suite
belongs to the `verify-graviton` CI lane. Fixture generation needs the memory-qualified
rig used for current hiding L2 proofs. Keep each producer in a separate process and
do not overlap producers with CI or another benchmark.

On that rig, pin the checkout and build the release binary. Record the full commit,
`Cargo.lock`, `rustc -Vv`, hardware, OS, actual available memory, and power/thermal state.
The tools' `--revision` value is explicitly an **operator-declared build revision**;
it is not a claim that the binary can attest its own source tree.

Example commands, on the rig, for one shape:

```sh
cargo build --release --locked -p qlab-bench
f2_revision=$(git rev-parse HEAD)
mkdir -p f2-results
target/release/qlab-bench f2price --shape p3 --symbolic-only --input-pcs hiding --rc 0 --report json --revision "$f2_revision" > f2-results/p3-price.json
/usr/bin/time -v target/release/qlab-bench f2fixture --shape p3 --out f2-results/p3.proof --revision "$f2_revision" --power 'AC; record hardware/thermal state separately' > f2-results/p3-fixture.json 2> f2-results/p3-producer.log
/usr/bin/time -v target/release/qlab-bench f2census --shape p3 --input-pcs hiding --rc 0 --proof-in f2-results/p3.proof --report json --revision "$f2_revision" > f2-results/p3-census.json 2> f2-results/p3-census.log
```

Repeat for `s3` and `r`, sequentially. Use different output paths for independent
repetitions: fixtures refuse overwriting. Produce two same-rig samples before publishing
measurements. Preserve raw memory units from `/usr/bin/time -v`; Linux reports max RSS
in KiB, while the JSON tool reports proof bytes and hash counts, **not peak memory**.
Collect the two processes' peaks separately; their serialized pipeline peak is their
maximum, not their sum. Timings from a counting verifier are instrumented timings.

The fixture envelope contains only the proof, canonical public values, shape digest,
current lane/PCS parameters, format version, and producer revision. It contains no
transaction witness or keys. These are bench fixtures made from the existing synthetic
L2 fixture builders, not captured user transactions. The envelope is bounded and rejects
trailing bytes. It is a bench format, not a new transaction/network wire format.

## What the outputs establish

`f2census` refuses a fixture with a different shape digest, PCS/lane, rc, noncanonical
public values, unexpected opening dimensions, missing randomizer, malformed salts,
wrong paths, or wrong fold count. It then verifies through both the live L2 config
and a counting mirror using the **same serialized proof**. Counting adapters delegate
to the same Keccak primitives; there is no counting prover.

On success, `measured_hash_work` is labelled **M**: leaf absorbs, path compressions,
Fiat–Shamir permutations, and individual transcript flush byte lengths. The geometry
is labelled **P**: it is inferred from source/configuration. Actual leaf/path counts
must equal that geometry; actual transcript permutations must be at least its
no-rejection-refill floor. Any mismatch fails the command instead of producing a
successful census. rc0 still has the randomizer commitment and salts.

`f2price` reads the actual witness-free AIR's symbolic constraints and counts
pointer-shared add/sub/neg/mul nodes. It reports maximum degree, hiding quotient chunks,
periodic column periods, and the unoptimized alpha fold. This is **P**, not a prover
measurement, a structural-CSE optimum, or a lowered register/row layout. It does not
allocate a trace or prove. Both modes report `complete_verifier_layout: false` and
`memory_gate_pass: false` until a separate completed circuit can justify either claim.

### Executable OOD algebra

`f2price` additionally reports `ood_arithmetic`: an explicit extension-field arithmetic
DAG for periodic evaluation, AIR selectors/constraints, alpha folding, quotient
recomposition and the final OOD identity. Its counts are **P**, without structural CSE,
constant folding or register allocation. Input reads and constants are counted separately;
inverse operations are explicit. This is executable algebra, **not an AIR**. The
`symbolic_air.not_lowered` list continues to name work missing from the recursive AIR.

`f2census`, after successful native proof verification, replays the uni-stark challenger
prefix including the randomizer commitment, evaluates that DAG on the actual openings,
and compares its periodic values, selectors, next-row point, quotient and folded AIR
constraints against the native routines. `ood_algebra.residual_zero` must be true.
Any disagreement fails the census. No extra proof is generated.

AIR selectors, periodic columns and the next-row point use the original **N** domain;
the trace commitment uses **2N**. Periodic coefficients are computed from public AIR
constants by IDFT during compilation, followed by explicit Horner operations at
`zeta^(N/period)`. First/last selectors retain the native unnormalized convention.
Each quotient chunk combines four **extension-valued** openings with extension-basis
constants, then applies the native split-domain interpolation weights. The randomized
PCS chunk commitment domains are not the recomposition domains. A zeta in the original
trace domain fails an explicit inverse-of-zero check; dimension mismatches fail before
input indexing. Unsupported symbolic sources are errors rather than zero-filled inputs.

The next implementation checkpoint must constrain these operations in a recursive AIR,
including every inverse (`x * inv = 1`), input read, write and register hold. It must also
account for randomizer and salt bindings, shape/config identity and shape-specific
fee/state transitions, plus the unresolved issue #78 work.
Recompute width and padded height from that implementation; do not copy the stage-zero
width budgets into an allocation as if they were verified dimensions.

`ood_arithmetic.register_schedule` now prices a last-use register schedule; census
also checks its sparse execution against every reachable DAG node. The separate
[register-machine reference](f2-register-machine.md) explains the bounded test-only
AIR and its explicit ROM cost. This does not change the full-layout/memory flags.

## Validation and limits

The CI regression suite includes sequential real S3/P3/R proof generation, both native
verifiers, geometry/counter agreement, and mutations of the randomizer, salts, rc0
nesting, P3's additional fold, and public values. Lightweight tests pin the paper
geometry and live AIR metadata and reject incompatible command/fixture inputs.
These test definitions are not a claim that CI has passed; the PR's exact-head CI result
is the evidence. Full recursive soundness, lowered width/height, mixed-shape aggregation,
and the memory gate remain unverified by these tools.

OOD regressions compare all three shapes against native algebra on deterministic
extension-field inputs, exercise every quotient chunk/basis coefficient, distinguish
N from 2N, and reject on-domain zeta, wrong dimensions and unsupported sources.
The existing real-proof test also checks the honest zero residual and mutations of
quotient coefficients, local/next openings, consumed public values, alpha and zeta.
These are algebra-only probes: native PCS rejection is not a substitute for their
comparisons, and passing them is not a claim of full recursive verification.
