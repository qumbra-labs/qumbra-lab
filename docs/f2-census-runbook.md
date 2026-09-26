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

The next implementation checkpoint must account for periodic evaluation, quotient
recombination/identity, randomizer and salt bindings, register lifetimes, shape/config
identity and shape-specific fee/state transitions, plus the unresolved issue #78 work.
Recompute width and padded height from that implementation; do not copy the stage-zero
width budgets into an allocation as if they were verified dimensions.

## Validation and limits

The CI regression suite includes sequential real S3/P3/R proof generation, both native
verifiers, geometry/counter agreement, and mutations of the randomizer, salts, rc0
nesting, P3's additional fold, and public values. Lightweight tests pin the paper
geometry and live AIR metadata and reject incompatible command/fixture inputs.
These test definitions are not a claim that CI has passed; the PR's exact-head CI result
is the evidence. Full recursive soundness, lowered width/height, mixed-shape aggregation,
and the memory gate remain unverified by these tools.
