# qumbra-lab M4 step 1a: interior-node recorder + census (run 1)

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev: gate-exit base 7a7921b + `claude/m4-tree-step1`
- prover: Plonky3 0.6.1 (pinned in Cargo.lock)
- power state: AC, idle rig
- input: one leaf `VerifierGateAir` **wide** proof committed at
  **b4/q40/g20/fp16/a16** (the aggregation lane). The interior node verifies a
  proof of THIS shape (2^16 × 3,626), **not** the M3 narrow proof (2^18 × 618)
  the leaf itself verified — so `m4gaterec` (M3-specific) cannot record it; the
  new `m4treerec` reuses the AIR-agnostic `m4gaterec::walk_with_cfg`.

## Interior-node workload — verifying ONE child leaf wide proof

| metric | value |
|---|---|
| keccak-f total | **7,503** (leaf-sponge 4,560 + compress 2,040 + challenger 903) |
| opened values / query | 7,260 (trace-local 3,626 + trace-next 3,626 + quotient 8) |
| reduced-opening values | **290,400** = 40 q × 7,260 |
| FRI rounds | 3 (log-arities [4, 4, 4]) |
| final-poly len | 16 |
| challenger draws | 65 |
| commitments (caps) | 5 (trace + quotient + 3 FRI) |
| native perms recorded | 8,138 |
| leaf proof size (fixed) | 779.6 KB |

Recorder acceptance: the recorded transcript **matched a native `verify()`** of
the leaf proof (permanent test `recorder_accepts_leaf`); the walk logic is
`m4gaterec::walk_with_cfg`, already native-cross-checked for M3.

## Two findings that shape M4 step 1 stage 2 (the interior circuit)

**1. The measured interior hash workload is ~23 % above the census projection.**
m4census Phase C projected the b4 interior fixed point at **6,083 keccak-f/wide-proof**;
the actual b4/q40 leaf proof measures **7,503**. The gap is the leaf-sponge term
(4,560): the census modeled a generic wide proof, but the real leaf opens
**7,260 values/query** (two full 3,626-col rows — trace-local + trace-next,
because the gate AIR has transition constraints), which sponges to more perms
than the model assumed. Still comfortably within the ~30 s / ~32 GB interior
envelope on the hash axis, but the projection is corrected upward.

**2. The interior is arithmetically ~11.6× heavier than the leaf.**
The reduced-opening (the dominant verifier arithmetic — m4price) is
**290,400 values** for the interior (40 q × 7,260) vs the leaf's own **25,000**
(20 q × 1,250, m4price). Verifying a *wide* proof opens two full wide rows per
query, so the interior node's reduced-opening arithmetic is an order of
magnitude larger than the leaf's. This is the concrete driver behind the flagged
**core risk** — the interior node's quotient/LDE (and thus peak RSS vs the 32 GB
envelope) will be materially heavier than the leaf's 11.9 GB; stage 3 measures it.

## What this unblocks

`m4treerec` produces the exact `Schedule` the interior verifier circuit (stage 2)
will prove against — the interior analogue of `m4gaterec` for M3. Numbers only;
no circuit and no envelope gate yet. A 2:1 interior node verifies **two** such
children + a public-digest merge, so its hash lane ≈ 2 × 7,503 + merge ≈ **15 k+
keccak-f** — the interior circuit's lane count, ~2× the leaf's 2,382.

## Deferred (stage-2 hardening)

Byte-exact native keccak-*sequence* cross-check (as in m4gaterec's
`walk_matches_native_hashing`) for the leaf recorder — deferred until the
interior circuit consumes the schedule and byte-exactness gates soundness.
Generalizing `record_verify` (test-module, currently bucket-AIR + CONSENSUS_CFG
bound) is the mechanism.
