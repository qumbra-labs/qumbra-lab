# M4 step 0b(ii): verifier-circuit layout (design, pre-build)

Working note for the full verifier-circuit build, in the M1.5b tradition
(layout design + anchor before the real thing). Inputs: the 0a hash census
(2,233 keccak-f/proof), the 0b(i) arithmetic census (28,800 ext-mul +
28,663 ext-add + 60 ext-inv), and the ext-mul bank anchor measured in this
PR. Everything here is layout planning — the build itself is the next PR.

## The rectangle

One AIR, one rectangle: **2,673 cols x 2^16 rows** (+1.5% cells over the
step-0a hash-only baseline that measured 456 ms / 2.87 GB at b4):

| lane | cols | rows used / 65,536 | role |
|---|---|---|---|
| wide Keccak (stock p3-keccak-air shape) | 2,633 | 53,592 (2,233 perms x 24) | Merkle leaves, path compressions, challenger transcript |
| ext-mul bank (this PR's anchor) | 12 | 28,800 | reduced openings, constraint DAG, alpha fold, folds, Horner |
| ext-add bank (batched 4/row) | 12 | 7,166 | additive halves of the above |
| routing / FS / flags [allowance] | ~16 | various | injection, challenge extraction, selectors |

Row budget clears 2^16 in every lane with slack; the binding lane is the
Keccak schedule (82% utilization).

## Subsystems for the build

1. **Keccak schedule program**: the 2,233-perm sequence (per query: leaf
   absorptions -> path compressions; plus the 173-perm challenger
   transcript) driven by a program ring, M3-bucket style. The schedule is
   fixed by the consensus config — same fixed-shape-AIR philosophy as the
   tx circuit, no in-circuit branching.
2. **Arithmetic banks**: the anchor's 12-col ext-mul row (measured: 32,768
   muls prove in 36–107 ms across lane configs, values cross-checked
   against p3's own ext arithmetic; 4 constraints, degree 2 — no quotient
   surprises) + an add bank batching 4 adds/row.
3. **Injection routing**: opened values (witness) must reach both the
   Keccak lane (as absorbed bytes) and the banks (as field elements). M3's
   equality-bank machinery is the precedent; the new wrinkle is
   base-vs-ext representation (opened main values are base field, FRI
   values ext) — route as 4-limb tuples throughout.
4. **Fiat–Shamir extraction**: challenges are bytes of Keccak-lane digests
   reinterpreted as field elements; needs a byte-packing gadget between
   the lane's u64 lanes and bank limbs. This is the least-explored gadget
   — budgeted inside the 16-col routing allowance, flagged as the build's
   main unknown.
5. **Batched ext-inv**: 60 inversions per proof via one product chain in
   the mul bank (~180 bank rows) + a single witness inverse checked by
   one mul row.
6. **Public surface**: inner commitments + inner public values enter as
   outer public values; the outer proof exposes a running digest binding
   (inner digest set, verified flag) upward — the tree-node interface.

## Acceptance (from aggregation-rung1 §6)

Leaf <= ~10 s / <= 32 GB: the composite projection is **~463 ms / ~2.91 GB
at b4** — margin ~20x on both axes. The build's job is to land inside,
plus semantics: positive test (verify a real M3 proof in-circuit) and
negative tests (tampered opening, wrong root, wrong challenge, bad fold).

## Estimate

Full 0b(ii) build: ~8–15 Claude session-hours (the FS byte-packing gadget
and the injection routing are the two real unknowns; banks and schedule
are mechanical after M3). Tree prototype (step 1) follows only after the
build reports measured numbers.

## Build status (2026-07-17, updated at session handoff)

| increment | what | status |
|---|---|---|
| 1 — skeleton | LaneBuilder composition + three lanes coexisting at projected cost (b4 = 476–561 ms / 3.58 GB / 597.9 KB) | ✅ lab PR #15, `m4skel` mode |
| 2 — injection routing | opened values -> keccak lane bytes + bank limbs (equality-bank precedent) | next |
| 3 — FS byte-packing | lane digests -> challenge field elements (top unknown) | after 2 |
| 4 — real schedule + binding + tests | verify a real M3 proof in-circuit; positive + negative tests; gate exit | after 3 |

Prover-performance lessons already learned (do not relearn): narrow eval's
Expr conversion to the columns actually used (a full-width collect runs per
LDE point, +70% prove); allocate trace buffers at full LDE capacity up front
(late reserve realloc = 3x RSS).
