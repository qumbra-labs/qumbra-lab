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

## R-PV (F2b-3): option (c) on every leaf PV group

Ruled on issue #750 (R-PV and its addendum). **C1 exposes every inner leaf PV unchanged**
as its own public values `[0, pv_len)`: 116 for S3, 128 for P3, 101 for R. No group is
compressed. No inner PV is hashed, summed or folded into another value. So option (c)
covers every group:

| shape | exposed groups (all of them) | compressed |
|---|---|---|
| S3 | anchor, nf1, nf2, cm1, cm2, fee, registry_root, nf3 | none |
| P3 | S3's first seven, vp1/vp2 (sign, amount, asset), nf3 | none |
| R | anchor, nf, cm, fee, old_root, new_root, asset, cm_seed | none |

C1 does **not** range-check them. Only two constraint groups read an inner-PV cell:
`bind_inner_pv` (PV = R⁻¹ · the absorbed word, and `canonical` keeps the word `< p`)
and `in_public` (the machine's input cells). The test `c1_accepts_an_out_of_range_leaf_pv`
shows it: the toy leaf's PV 1 is far above 2^16, and C1 is SAT on it. The consumer of the
aggregation proof must therefore apply `seam::check_leaf_pvs(shape, c1_pvs)` before it
accepts. That check refuses a PV outside its width and names it by group and index
(e.g. `` `fee[0]` ``).

The widths are **not restated**. `seam::leaf_pv_widths` reads them from the leaf AIRs' own
PV builders (`qlab_air::l2::pv_vec_l2`, `l2p::pv_vec_l2p`, `l2r::pv_vec_r`, re-exported by
`qlab-l2`) as the bit length of each slot at saturated typed inputs:

- **16 bits** for every `& 0xffff` chunk (digests, fee, vPublic amounts);
- **1 bit** for P3's two vPublic signs (`redeem as u32`);
- **32 bits** for the asset ids P3's vPublic and R expose (`as u32`). This is vacuous as a
  native check, since KoalaBear's p < 2^31 and every PV is canonical. In-AIR, each of these
  slots is equated to an asset accumulator cell.

`audit_pv_bits()` (lab issue #758) is not on main. When it lands, pin it equal to this table.

## F2b-4: the wrapper runs (`f2wrap`)

`f2wrap` loads an `f2fixture` envelope and admits it exactly as `f2census` does
(metadata, geometry, the live L2 verifier). It then builds the **full-size** C1 and C2 of
that one leaf, with C2 covering all 43 query slots:

- `--check` scans every row of both traces with p3-air's constraint evaluator. This is the
  row loop of `p3_air::check_constraints`; `qlab_air::l2test` wraps the same loop, but it is
  test-only by its Cargo contract. It then runs `check_seams`, `check_coverage` and
  `check_leaf_pvs`, and checks that each AIR has degree ≤ 3 and that the built dimensions
  equal the `price::composed_*` plan. No proving.
- `--prove --outer b2|b4` proves C1 and C2 under the **non-hiding** outer config (stage-0
  ruling 1: `qlab_consensus::legacy`). The lanes are the M4 interior's own, now named
  constants `m4interior::INTERIOR_B2_CFG` (b2/q86/g22/fp16/a16) and `INTERIOR_B4_CFG`
  (b4/q43/g22/fp16/a16). It verifies both proofs natively and reports widths, heights,
  constraint counts, degree, proof bytes, and prove and verify wall time.
  `--component c1|c2` proves one component only (the default is both). C1 is always
  built, because its seam feeds C2.
- **Budget:** `--max-cells` (default 1,500,000,000) is checked against the plan
  **before the fixture is read or any trace or ROM exists**. The C1/C2 constructors check
  it again before they allocate. Components are built one at a time, and each trace is
  dropped before the next is built. A process's peak is therefore its larger component's.
- **Output:** JSON on stdout, same envelope as `f2census`, with `--revision`. The mode writes
  no files. A run with a failed check still prints its report, then exits 2.

**[P] plan for S3** (`price::composed_*`, the #750 stage-0 k-model
`peak_GiB ≈ k × width × 2^(h−18)`, k_b2 = 0.00265645, k_b4 = 0.00427969). The report
prints the same numbers under `plan.expected_peak_gib`:

| component | columns × rows [P] | k-model b2 [P] | k-model b4 [P] |
|---|---|---:|---:|
| C1 | 11,746 (+2,227 periodic ROM) × 2^15 | 3.900 GiB (4.640 with ROM) | 6.284 GiB (7.475 with ROM) |
| C2 | 5,058 × 2^17 | 6.718 GiB | 10.823 GiB |

The k-model was fitted on the legacy M4 interior. It is a planning model, not a bound, and
has never been calibrated on these AIRs.

### Box commands (coordinator, memory-qualified rig)

Run sequentially and alone: no CI, no other benchmark. Record commit, `Cargo.lock`,
`rustc -Vv`, hardware, `MemTotal` and power state, as above. `noclobber` makes the shell
refuse to overwrite a report. Fixtures refuse to overwrite anyway.

```sh
set -o noclobber
cargo build --release --locked -p qlab-bench
rev=$(git rev-parse HEAD); bin=target/release/qlab-bench
power='AC; record hardware/thermal state separately'
mkdir -p f2b4
for pass in 1 2; do
  /usr/bin/time -v $bin f2fixture --shape s3 --out f2b4/s3-$pass.proof --revision "$rev" --power "$power" \
    > f2b4/s3-fixture-$pass.json 2> f2b4/s3-fixture-$pass.time
  /usr/bin/time -v $bin f2wrap --shape s3 --proof-in f2b4/s3-$pass.proof --check --revision "$rev" --power "$power" \
    > f2b4/s3-check-$pass.json 2> f2b4/s3-check-$pass.time || break
  /usr/bin/time -v $bin f2wrap --shape s3 --proof-in f2b4/s3-$pass.proof --prove --outer b2 --revision "$rev" --power "$power" \
    > f2b4/s3-prove-b2-$pass.json 2> f2b4/s3-prove-b2-$pass.time
  /usr/bin/time -v $bin f2wrap --shape s3 --proof-in f2b4/s3-$pass.proof --prove --outer b4 --revision "$rev" --power "$power" \
    > f2b4/s3-prove-b4-$pass.json 2> f2b4/s3-prove-b4-$pass.time
done
```

If `--check` exits non-zero, **stop**. `report.result.checks` names the failed check, and
`sat_scan.first_violations` names the row and constraint group. Post that before any
prove run. To attribute a peak to a component, add `--component c1` or `--component c2` in
separate processes.

**Reading the memory gate.** Peak RSS is `Maximum resident set size (kbytes)` in each
`.time` file: GiB = kbytes / 1024². The JSON never contains a measured peak.

- **Memory gate pass** means: every `f2wrap --prove` process, at both outer lanes and in
  both passes, peaks at **≤ 60 GiB** [M] (stage-0 ruling 2: rigs are r7g.2xlarge with 61 GiB
  usable), and its report shows `native_verified: true` for each proved component.
- **Separately**, report whether each peak is **≤ 32 GiB**, the named 32 GiB class. This is
  a second verdict, not the gate.
- The `f2fixture` producer (the hiding **transaction** prover, 13.727 GiB at S3 per F2b-0)
  and the `--check` process are **not** aggregation memory. Record them, but do not gate on
  them. A serialized pipeline's peak is the maximum of its processes, not their sum.
- Also record against F2b-4's acceptance: `c1.built.max_degree` and `c2.built.max_degree`
  ≤ 3, and `proof_bytes`, `prove_seconds` and `verify_seconds` per component. Two passes
  must agree before any number is published.

**Not established by this change:** no full-size trace has been built, scanned or proved.
Local runs are forbidden, and CI runs only the toy and 2-query instances. The plan-equals-
built check, the SAT scans at 43 queries and every prove number are the box run's to measure.
