# M4 step 0b(ii) increment 4 — status (relay handoff)

Branch `claude/m4-0bii-inc4`. This session (Opus 4.8) picked up the Stage-1 +
Stage-2 relay and executed `docs/m4gate-inc4-spec.md`. **STATUS: PARTIAL.**
The positive gate passes and two of the four gate-exit negatives bind; the
ext-arithmetic constraint pipeline (the bulk of spec §2.1–2.4) is the
remainder. Everything below is reproduced from tests in
`crates/qlab-bench/src/m4gate.rs`.

## What the first action found

Per spec §0, the flagged `gate_rectangle_satisfies` was run first. It
**failed** (row 119, constraint #4135), i.e. the previous session's discarded
edit had not greened it. The rectangle was "witness green" (simulator
self-checks pass) but the *present* AIR constraints rejected the genuine M3
proof. Two present constraints were mis-specified; both are correctness fixes,
not weakenings.

## Stage A — positive test green (commit 9b90760)

1. **GROUPREQ off-by-one** (flush-start draw-group gate). Draws are hosted on
   the *consumer* flush's block 0 (its chained preimage[0..16] == the producer
   digest, so the FS gadget squeezes the producer digest there). The group
   that gates F(k) is thus drawn *during* F(k)'s own block 0 and is never
   complete before F(k) starts. The invariant is: exactly k-1 groups are drawn
   by the last block of F(k-1). So `GROUPREQ[k] = k-1` for k=1..7
   (alpha..beta3), was zeta..pow. EXH stays `G_DONE` (read only at F7's last
   block, where head==7 != DONE, so NEEDL==0 and the post-F7 refill gate still
   holds). The witness `need` fill and the constraint read the same array, so
   one constant change fixes both. Verified uniform across all 7 flush
   boundaries via `dump_trace`.

2. **C5 (trace-leaf last absorb block) carry boundary.** 5 fresh u32 words
   pack 2-per-u64-lane; word 4 fills lane 2's low half (limbs 8,9) and the high
   half (limbs 10,11) is an unused zero pad in the overwrite-mode sponge. Only
   limbs 12..100 carry the producer output. Carry bound 10→12, plus pin the pad
   half (limbs 10,11) to zero (anti-smuggle). Confirmed against the recorder's
   overwrite-mode semantics and the live limb values.

`gate_rectangle_satisfies` and all other m4gate tests pass after these two.

## Stage B — gate-exit negatives + coverage map (commit f6af812)

`tamper_coverage` probe result (UNSAT = caught by a constraint, SAT = free):

| gate-exit negative | tamper point | status |
|---|---|---|
| 2 wrong root | flip an outer public value (cap limb) | **UNSAT (bound)** |
| 1 tampered opening | flip a query leaf preimage limb | **UNSAT (bound)** |
| 3 wrong challenge | flip an accepted field-draw / CHAL limb | SAT (unbound) |
| 4 bad fold | flip a running-fold-eval (RUNEV) limb | SAT (unbound) |
| (bank sanity) | flip a mul-bank output | UNSAT (bound) |

Negatives 1 and 2 are permanent passing tests (`gate_neg_wrong_root`,
`gate_neg_tampered_opening`). Negatives 3 and 4 are written but `#[ignore]`d
with the exact remainder in the attribute — **not weakened to pass**. Un-ignore
them when the pipeline lands.

Root cause of the two remainders: `eval` leaves the entire ext-arithmetic
pipeline as free witness — `extmul` is unused in `eval`. Free regions:
challenge assembly (COEF/CURCH/CHAL), reduced openings (PZACC/PREG), fold
ladders (SCR/BREG/RUNEV), final poly (FPREG), ext-inv (INV2S/INVZ/INVZN), and
the FS draw gadget internals (FSBITS/FSACC/accept). The structural half —
keccak lane, Merkle path/cap, scheduling rings, banks — *is* constrained, which
is why negatives 1 and 2 already bind.

## Column accounting (spec §2.7) — from `dump_cols`

Total **3,532 cols × 2^16 rows, 2,382 lane perms** (unchanged by Stage A/B —
the two fixes add no columns).

```
KECCAK lane                              2633
MUL bank / ADD bank                        24
gate block (GB..GATE_WIDTH)               875
  routed-word + canonicity                 46
  XOR register file (OREG/PBIT/OBIT)      196
  FS draw gadget                           26
  draw scheduling (GRP/COEF/CURCH…)        39
  challenge/index regs (CHAL…IDXR)         56
  flush automaton (FRING…)                 49
  phase/query sched                        26
  query program ring (PR 103 + PD 15 …)   189
  index bits                               22
  asm pipeline (CZ*/POS/VC/…)              38
  running-sum/arith regs (PREG…, FPREG)   168
  dup transport (F2DIG…)                   20
  --------------------------------------------
TOTAL                                     3532
```

Growth vs the post-inc-3 plan (2,685): +847, all in the gate block (inc-3's
routing allowance was ~28 cols). Dominant contributors: XOR register file
(196) and query program ring (189) and running-sum/arith registers (168) — the
real verifier machinery the inc-1/inc-3 skeleton did not yet host. This growth
is structural (final width); it does not change when the remaining constraints
land, since constraints add quotient chunks, not trace columns.

## Canonicity disposition (spec §2.6)

**Not yet resolved — remainder item.** The `< p` comparator columns
(HB0/HB1/TA/TOPA/LBNZ/LONZ, and the routed words W0C/W1C) are *filled* by
`fill_canon` in the trace builder but are **never referenced in `eval`** (no
`cv(HB0)…`). So the v vs v+p byte-alias is not killed by any active constraint.
The inc-2 deferral ("killed transitively by digest binding") cannot be verified
yet, because the routed-word consumption + digest binding it would rely on is
itself part of the unbuilt ext-arith/asm pipeline. Disposition to record: the
canonicity constraint must be *added* (or its transitivity mechanically shown)
as part of building the routed-word → asm → digest binding.

## Bench (spec §4) — deferred, with reason

No `m4gate` bench mode is wired in `main.rs` (the `prove`/`verify` path is
unused scaffolding from Stage 2). More importantly, prove-time / peak-RSS /
fixed-width-KB on the *current* partially-constrained AIR would materially
under-report the finished rectangle: the missing ext-arith constraints add
quotient degree and chunks (→ larger quotient, more openings, higher prove
time and proof size). Per this repo's bench discipline (a number is publishable
only when it represents the thing), the prove/RSS/KB anchors are deferred to
constraint completion. The **structural** dimensions are final and reported
above (3,532 cols × 2^16, 2,382 perms).

## Remainder (for the next relay session)

In rough dependency order:

1. **FS draw gadget binding** (spec §2.2 base) — bind FSBITS/FSACC/accept to
   the sponge squeeze; reuse the inc-3 pattern in `m4route.rs`
   (`fs_matches_native_challenger`). Also bind the GRP/COEF ring rotations to
   the draw-complete signal (GROT/CROT columns already exist) — this is the
   schedule-binding half of spec §2.1 for draws, and gives the GROUPREQ gate
   real teeth.
2. **sample_bits** (§2.2) — LE-bytes-from-digest-end, mask to log2(domain), no
   rejection; native cross-check like inc-3.
3. **Ext-challenge assembly** (§2.3) — 4 accepted base draws → 4-limb ext tuple
   into CHAL; cross-check limb order vs `p3_field`.
4. **Ext-arithmetic pipeline** (§2.1) — reduced openings (PZACC/PREG), fold
   ladders (SCR/BREG/RUNEV), final poly Horner (FPREG); use the `extmul`
   helper already defined (but unused) in `eval`. Closes `gate_neg_bad_fold`.
5. **Batched ext-inv** (§2.4) — 60 inversions via one mul-bank product chain +
   single witnessed inverse; layout-doc subsystem 5.
6. **Canonicity** (§2.6) — constrain the `< p` comparator (above).
7. **Public surface** (§2.5) — the outer PVs already expose caps + inner PVs;
   add the running-digest / verified-flag upward binding for the tree node.
8. **Bench** (§4) — wire an `m4gate` mode (copy `m4route`/`m4skel`), two configs
   (b4/q40, b16/q20), two fresh runs → run1.md/run2.md.

Debug tooling left in place for the relay: `dump_constraint` (constraint index
→ referenced column regions, `colname` mapper), `dump_trace` (de-Monty'd
flush/draw schedule at each last-block boundary), `dump_cols` (this table),
`tamper_coverage` (the UNSAT/SAT map).

Note on encodings for the next session: the whole trace is R-homogeneous
(Monty representatives). `to_unique_u32()` returns the Monty limb, so field
ONE prints as 33554430 (= R); divide by R / compare to `Val::ONE` to read
logical values. Scheduling/selector columns are ordinary field elements
(from_bool/from_u32), not extra-Monty'd.
