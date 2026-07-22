# Issue #32 re-bench — diversifier-dependent rkm = H(nk ‖ D_R ‖ d)

The circuit change (issue #32) absorbs the 16-byte address diversifier `d` into
the recipient-key-material derivation: `rkm = H(nk ‖ D_R ‖ d)`. This doc records
the consensus-lane re-bench and the aggregation-leaf re-verify, per the bench
discipline (reproduced twice, `/usr/bin/time -l`, zero swap).

## Environment

- hardware: Apple M5 Max, 36 GiB RAM
- OS: macOS 26.5.2
- qumbra-lab rev measured: `7781c15` (the circuit + wallet lockstep commit)
- prover: Plonky3 0.6.1 (pinned in `Cargo.lock`)
- power state: AC, cool
- bench: `cargo run --release -p qlab-bench -- bucket`

## Headline: the byte delta is ZERO

The diversifier absorbs into **already-committed** witness columns (W5/W6, which
the ACM perm already carries) of the **same** ARKM permutation, and the pad
merely shifts within that perm's rate. So the proof **structure** is unchanged —
same **83 perms**, same **617 cols × 2^18 rows**, same queries/FRI — and the
fixed-width (production-proxy) proof size is therefore **byte-identical**:

| metric | pre-#32 (issue #22 baseline) | post-#32 | delta |
|---|---|---|---|
| consensus fixed bytes `b16/q20/g22/fp16/a16` | 139,721 B | **139,721 B** | **0 B** |

Well inside the "stop if delta > 2 KB" bound — in fact exactly zero, because a
fixed-width encoding's length is a function of proof structure, not values.
(The postcard/varint size is value-dependent and shifted slightly to 164,521 B —
a codec artifact on the differing digest values; the gate uses fixed bytes.)

## Consensus lane, reproduced twice (zero swap)

`bucket` mode proves all nine ladder configs; the consensus gate config is
`b16/q20/g22/fp16/a16`.

| run | prove ms | verify ms | fixed B | postcard B | verdict | swaps |
|---|---|---|---|---|---|---|
| 1 | 1810.0 | 21.6 | 139,721 | 164,521 | PASS | 0 |
| 2 | 1781.0 | 20.2 | 139,721 | 164,521 | PASS | 0 |

- Gates: ≤ 150 KB and ≤ 3,000 ms → **PASS** on both dimensions (136.4 KB /
  ~1.8 s), unchanged from before #32.
- `/usr/bin/time -l`: **`0 swaps`** on both runs; whole-run peak memory footprint
  23.86 / 23.97 GB (dominated by the heavier low-blowup ladder lanes the bench
  also proves; the b16 consensus lane alone is ~13–15 GB, per M2/M3).

Full ladder (run 1), fixed KB, for context — every lane's verdict is unchanged
from the issue #22 baseline:

```
b16/q20/g22/fp32/a16  102 bits  1700 ms  136.7 KB  PASS
b16/q20/g22/fp16/a16  102 bits  1810 ms  136.4 KB  PASS   <- consensus
b16/q19/g24/a16       100 bits  1799 ms  130.7 KB  PASS
b16/q23/g10/a16       102 bits  1708 ms  153.7 KB  FAIL
b32/q18/g10/a16       100 bits  3367 ms  128.3 KB  FAIL (prove > 3 s)
b8/q27/g19/a16        100 bits  1015 ms  171.6 KB  FAIL
b8/q30/g10/a16        100 bits  1022 ms  188.3 KB  FAIL
b4/q40/g20/a16        100 bits   655 ms  236.4 KB  FAIL
b4/q45/g10/a16        100 bits   610 ms  263.3 KB  FAIL
```

## Aggregation leaf gate re-verifies the NEW M3 shape

The M4 leaf gate proves-in-circuit a real M3 consensus proof. Its recorders
(`m4gaterec`) regenerate that M3 proof **in-process** via `build_bucket`, which
now produces the diversifier-dependent derivation. Because the M3 proof is
byte-identical in structure (see above), the leaf gate's width and FS schedule
are unaffected and it accepts the new proof unchanged:

- **`cargo test --release -p qlab-bench` → 80/80 green** (reproduced; the run
  regenerates and verifies the new-shape M3 proof through the leaf gate).

## STOP-POINT invariants (issue #32 deliverable 1)

The issue priced the change at "~few perms" and asked to stop if absorbing `d`
forced > 1 extra perm or any height change. Measured outcome — **better than
priced, no stop needed**:

| invariant | before | after |
|---|---|---|
| perms (`BUCKET_PERMS`) | 83 | **83** |
| trace height | 2^18 | **2^18** |
| columns | 617 | **617** |
| max constraint degree | ≤ 3 | **≤ 3** |
| extra permutations | — | **0** |

`d` is pinned to the public surface through `rkm → cm → membership → anchor`;
`nf = H(nk ‖ ρ)` is diversifier-independent (asserted by the circuit test
`rkm_diversifier_dependent`: distinct `d` → distinct anchor, identical `nf`).
