# M4 step 0b(ii) increment 4 — status (relay handoff)

Branch `claude/m4-0bii-inc4`. This session (Opus 4.8) picked up the Stage-1 +
Stage-2 relay and executed `docs/m4gate-inc4-spec.md`. **STATUS: PARTIAL.**
The positive gate passes and **three of the four** gate-exit negatives bind
(wrong-root, tampered-opening, wrong-challenge); only bad-fold awaits the
ext-arithmetic fold pipeline. Everything below is reproduced from tests in
`crates/qlab-bench/src/m4gate.rs`.

**Update (Stage D):** the FS/challenge binding is built — see that section
below. **Update (Stage E):** `sample_bits` is built — every FRI query index is
now tied to the FS-sampled digest bits. **Update (Stage F):** the draw-group
schedule (GRP ring + GROT + PoW value) is bound. The coverage table and
remainder are updated accordingly. **Update (fold map):** the fold pipeline
(the sole remaining negative, bad-fold) has been fully mapped — see the
"Fold-pipeline execution map" appendix at the end for the next session.

## ROADMAP line (milestone-level, for the coordinating session to sync)

Drop-in replacement for the design-repo `ROADMAP.md` "increment 4 next" cell —
milestone granularity, not the per-stage (A–J) breakdown, which is lab
commit-level detail and belongs here, not in the roadmap. **Do not edit the
design repo from the lab session** (spec §6); this is prepared text for the
coordinating session:

> **increment 4 IN PROGRESS (gate exit):** the verifier's structural + FS/draw
> half is soundly bound — FS challenge gadget + ext-challenge assembly,
> `sample_bits` query-index binding, draw-group schedule (GRP ring/GROT/PoW),
> and the query-point/inverse/s-chain arithmetic (XREG/XFIN, INVZ/INVZN via the
> `ZN = zeta·g_trace` relation, INV2S). **3 of the 4 gate-exit negatives bind**
> (wrong-root, tampered-opening, wrong-challenge) plus query-index / GRP-schedule
> / value-schedule bindings; positive accepts the real M3 transcript. The
> ext-arithmetic **fold pipeline is being built bottom-up** (value-carry
> schedule + VC/GPB done; remaining: BREG ladder → M_FHI folds → M_RO reduced
> opening + PZACC → final-poly Horn → closes `bad_fold`). All added constraints
> deg ≤ 3 except the M_S mux (deg 4, within the fold's deg-5 budget); rectangle
> unchanged at 3,532 cols × 2^16. **Pre-existing deg-6 flush-automaton products
> must be reduced before the bench** (Stage-2 legacy, not this increment). Lab
> branch `claude/m4-0bii-inc4`, stages A–J.

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
| 3 wrong challenge | flip an accepted field-draw FSACC / CHAL limb | **UNSAT (bound, Stage D)** |
| 4 bad fold | flip a running-fold-eval (RUNEV) limb | SAT (unbound) |
| (bank sanity) | flip a mul-bank output | UNSAT (bound) |

Negatives 1, 2, 3 are permanent passing tests (`gate_neg_wrong_root`,
`gate_neg_tampered_opening`, `gate_neg_wrong_challenge_fs` +
`gate_neg_wrong_challenge_chal`). Negative 4 is written but `#[ignore]`d with
the exact remainder in the attribute — **not weakened to pass**. Un-ignore it
when the fold pipeline lands.

Root cause of the *remaining* bad-fold gap: `eval` still leaves the ext-arith
pipeline as free witness — `extmul` is unused in `eval`. Free regions: reduced
openings (PZACC/PREG), fold ladders (SCR/BREG/RUNEV), final poly (FPREG),
ext-inv (INV2S/INVZ/INVZN). The FS draw gadget and challenge assembly are now
bound (Stage D).

## Stage D — FS/challenge binding (closes wrong-challenge)

The FS draw gadget and ext-challenge assembly are now constrained in `eval`,
mirroring the proven inc-3 gadget in `m4route.rs`. The soundness chain:

  sponge digest (preimage limbs, bound by keccak lane + chain gate)
    → FSBITS  (limb consistency: `fs*(limb_mux - (b_hi + 2^8*b_lo))`)
    → FSACC / masked  (even-row byte load; 31-bit masked value)
    → FSACCEPT  (rejection comparator: reject iff bits 24..30 all one AND
       low-24 nonzero — the native SerializingChallenger32 resample rule)
    → CURCH  (accepted field draws load COEF-ring-selected limbs)
    → CHAL[grp]  (every 4th accepted draw assembles the GRP-ring-selected
       ext challenge; GRP-phase field groups 0..6 only — PoW/query-index
       bits draws are gated out by `field_grp` and left for sample_bits).

Two independent tampers are now caught (`gate_neg_wrong_challenge_fs`,
`gate_neg_wrong_challenge_chal`): flipping an accepted draw's FSACC (byte
gadget) and flipping an assembled CHAL limb (assembly binding). All deg ≤ 3.

Residual (small) sub-item: **FSGATE position** is not yet schedule-bound — a
prover may set FSGATE=1 on extra rows. This does not open the tested tampers
(the digest→byte→masked→CHAL chain still pins each assembled challenge to the
real transcript, and the comparator/limb-consistency hold on any FS row), but a
full soundness proof wants FSGATE pinned to the draw-hosting schedule (part of
spec §2.1's periodic-schedule binding). Noted for the fold-pipeline session.

## Stage E — sample_bits (query-index binding)

The `sample_bits` variant (spec §2.2) reuses the Stage-D byte gadget: the
native challenger masks a 4-byte pop to the low `log_max` (= 22) bits with no
rejection. On a query-index draw's odd row the value is
`IDXR[q] = FSACC (bits 0..16) + FSBITS[0..6] << 16`, bound into the GRP-ring-
selected `IDXR[q]` (grp = G_IDX0 + q). Since the query-program routing already
constrains `recompose(IDXB) == QSEL-selected IDXR[q]`, this closes the loop
**digest bits → IDXR → IDXB → which leaf each query opens** — a prover can no
longer choose favorable FRI queries. New passing test
`gate_neg_wrong_query_index` (flip IDXR[0]); all Stage-E constraints deg ≤ 3
(the 20 IDXR bindings are the only additions).

## Stage F — schedule binding: GRP ring + full GROT + PoW value

The draw-group schedule is now bound to the FS gadget:

- **GROT** (group-advance signal) is fully constrained:
  `GROT = CROT·(coef==3) + FSODD·bits_grp`, i.e. a field challenge's 4th
  accepted limb OR any PoW/query-index (bits) draw's odd row.
- **GRP ring** left-rotates only on GROT (was free witness) — a prover can no
  longer advance the group schedule out of step with the draws. This gives the
  GROUPREQ flush-start gate (Stage A) real teeth and locks the challenge/index
  assembly to the correct groups. New test `gate_neg_grp_schedule`.
- **PoW value** (grp = G_POW): the low GRIND_BITS (= 20) of the sampled value
  are constrained to zero (`FSACC + FSBITS[0..4]<<16 == 0`) — the grind check.

All Stage-F additions deg ≤ 3. Suite 13 passing tests + 1 ignored (`bad_fold`).

## Degree budget — PRE-EXISTING violation of the deg≤3 house rule

`dump_constraint` reports **max degree 6** (histogram: deg1:36, deg2:2863,
deg3:1378, deg4:185, deg5:17, deg6:1). The deg-6 argmax is constraint #4165 —
the Stage-2 flush-automaton `BLKCNT` phase-evolution constraint
(`phasegate*(148-BLKCNT)`, where `phasegate = sf(23)*BLKLAST*ringsel(7)*
grpdone*phc` is a 5-factor product). The deg 4/5/6 constraints (203 total) are
all pre-existing Stage-2 boundary/flush products, **not** introduced this
session (the Stage-D FS/assembly constraints are all deg ≤ 3). Stage 2 never
wired a prove path, so this never surfaced. It matters for the bench (§4): the
quotient degree is 5, needing more quotient chunks than a deg≤3 sizing budgets,
and a deg≤3-configured prover would misbehave. **Remainder item:** factor the
phasegate chain (and the other deg≥4 boundary products) through materialized
selector columns to restore deg ≤ 3 before benching.

## Column accounting (spec §2.7) — from `dump_cols`

Total **3,532 cols × 2^16 rows, 2,382 lane perms** (unchanged by Stage A/B/D —
none add columns; Stage D reuses the pre-allocated FS/draw-scheduling cols).

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

DONE this session: (Stage A) two constraint-timing fixes → positive green;
(Stage B) negative scaffold + coverage; (Stage C) col accounting; (Stage D)
FS draw gadget + ext-challenge assembly (spec §2.2 byte gadget + §2.3), closing
`gate_neg_wrong_challenge`; (Stage E) `sample_bits` query-index binding (§2.2),
adding `gate_neg_wrong_query_index`.

In rough dependency order, still open:

1. **Degree reduction to ≤ 3** (pre-existing, blocks the bench) — factor the
   Stage-2 flush-automaton deg 4/5/6 boundary products (phasegate chain etc.)
   through materialized selector columns. See the degree-budget section.
2. **FSGATE schedule binding** (§2.1) — pin FSGATE to the draw-hosting rows so
   the gadget cannot be spuriously activated on a non-digest perm. This is the
   last piece of the draw-schedule binding (PoW value, GROT, and the GRP ring
   are done in Stage F). Deeper because draw counts per perm vary; see the
   Stage-D residual note.
3. **Ext-arithmetic pipeline** (§2.1) — reduced openings (PZACC/PREG), fold
   ladders (SCR/BREG/RUNEV), final poly Horner (FPREG); use the `extmul`
   helper already defined (but unused) in `eval`. Closes `gate_neg_bad_fold`.
6. **Batched ext-inv** (§2.4) — 60 inversions via one mul-bank product chain +
   single witnessed inverse; layout-doc subsystem 5.
7. **Canonicity** (§2.6) — constrain the `< p` comparator (above).
8. **Public surface** (§2.5) — the outer PVs already expose caps + inner PVs;
   add the running-digest / verified-flag upward binding for the tree node.
9. **Bench** (§4) — after degree reduction: wire an `m4gate` mode (copy
   `m4route`/`m4skel`), two configs (b4/q40, b16/q20), two fresh runs →
   run1.md/run2.md.

Debug tooling left in place for the relay: `dump_constraint` (constraint index
→ referenced column regions, `colname` mapper), `dump_trace` (de-Monty'd
flush/draw schedule at each last-block boundary), `dump_cols` (this table),
`tamper_coverage` (the UNSAT/SAT map).

Note on encodings for the next session: the whole trace is R-homogeneous
(Monty representatives). `to_unique_u32()` returns the Monty limb, so field
ONE prints as 33554430 (= R); divide by R / compare to `Val::ONE` to read
logical values. Scheduling/selector columns are ordinary field elements
(from_bool/from_u32), not extra-Monty'd.

## Fold-pipeline execution map (for the next focused session)

This is the last remaining gate-exit negative (`bad_fold`) and the largest
piece. It is a deeply interconnected monolith — there is **no small sound
partial** that closes bad-fold, because the fold-leaf consistency needs HIT
bound, HIT needs the VC/GPB machinery, and the fold arithmetic needs BREG which
needs the bank-routed s/b ladders + reduced opening + final Horn. Build it as
one subsystem, bottom-up, testing the positive after each layer.

### What the pipeline computes (per query), from the witness micro-code

All arithmetic runs through the mul/add banks (`bank_mul`/`bank_add`, already
constrained: MUL c=a×b, ADD c=a+b) **or** directly over ext columns. A
sim-only `mchain` register (NOT a trace column) threads chains across
consecutive bank rows. Micro-codes (MSEL, per-perm, query phase only):

- **M_X1** (22 rows): `x = GEN·∏(kx[r] if idx-bit r else 1)` — chained bank_mul
  → XREG. **M_FIN** (8 rows): same shape → XFIN.
- **M_INV** (2 rows): witness `inv_z = 1/(zeta−x)`, `inv_zn = 1/(zeta_next−x)`;
  bank_add_c then bank_mul, product must be ONE. → INVZ, INVZN.
- **M_S0..S3**: `s = ∏(sk if bit else 1)` chained bank_mul; then witness
  `inv_2s = 1/(2s)` (2s·inv_2s == 1). → INV2S.
- **M_B0..B3** (BREG ladder): `breg[0] = beta·inv_2s` (bank_mul), then
  `breg[l] = 2·breg[l-1]²` (bank_mul square, ×2). → BREG (4×4 cols).
- **round-0 leaf fold** (value-capture, NOT a micro-code — runs on CONSF rows):
  vc even → `PBUF = v`; vc odd → `SCR[i] = (PBUF+v)·half + BREG[0]·kf[rf][0][i]·
  (PBUF−v)`, i = vc/2. **Column-based** (v = ext(ASM0,ASM1,W0C,W1C), PBUF, SCR,
  BREG all cols) — deg 2, no bank needed.
- **M_RO** (9 rows): assemble reduced opening `ro` from P0,P1,PX0,PZACC,A0,A1,A2,
  INVZ,INVZN via banks (SCR[0..4] scratch) → RUNEV.
- **M_FHI0..3** (higher fold rounds): `outv = (SCR[2i]+SCR[2i+1])·half +
  BREG[l]·kf[rf][l][i]·(SCR[2i]−SCR[2i+1])` → SCR[i] or (last) RUNEV.
  **Column-based** — deg 2.
- **M_HORN** (15 rows): final-poly Horner `acc = FPREG[15]; acc = acc·XFIN +
  FPREG[14−r]` via banks; at r=14 assert `acc == final_eval` **and
  `acc == RUNEV`** (the final fold compare).

### The soundness thread

`RUNEV` is set by M_RO (= ro) then each M_FHI (= folded_r), and read at (a) each
fold leaf's `index_in_group` position — `v == RUNEV` (the FRI consistency: the
previous round's fold must reappear as this round's opening, bound to the
sponge), and (b) the final Horn compare (`RUNEV == final_eval`). The reduced
opening ties RUNEV to the trace/quotient openings (PZACC/PX accumulation:
`pzacc += preg·v`, `preg *= fri_alpha`, over all opened values + the dup zeta
values). Binding *all* of RUNEV, the ladders, and the openings is required —
partial binding lets a prover pick free intermediates.

### Suggested build order (each layer: positive stays green, add a negative)

1. **[DONE — Stage G]** Value-carry-row schedule + VC/GPB. The asm/PX carry
   selectors (CZD/CZ7/CF/CX0/CX1) are bound to the role/phase schedule + row
   ranges; the **POS** half-position ring toggles on `casm = CZD+CZ7+CF`;
   **CONSZ/CONSF** are the pos==1 completion flags; the **VC** value-counter
   ring (16-slot one-hot) rotates on CONSF and resets at leaf-start; **GPB**
   (index-in-group bits) is muxed from IDXB by the fold-round dparam. Remaining
   in this layer: **HIT** (= [VC == GPB]) — needs an equality gadget (one-hot
   dot-product is deg 5, or add an inverse witness); do it with the leaf fold.
   **[DONE — Stage H]** the x/x_fin chains: XREG = GEN·∏(kx if idx-bit else 1)
   and XFIN over the high bits, via the mul-bank chain (cross-row `mchain`
   threading: `nv(mul_a) == cv(mul_c)`, capture into XREG/XFIN, carry
   otherwise). NOTE the constant-injection gotcha: `cf(x)` in `eval` equals
   `scale(x)` (round-trips through the Monty limb), so the *native* x-chain
   uses `as_canonical_u32` instead — see the `cn` helper.
2. **PBUF/SCR round-0 leaf fold** (column, deg 2) — needs BREG[0]; add HIT here.
3. **[DONE — Stages J/K]** s-chain/INV2S (Stage J) + BREG ladder (Stage K,
   M_B): `breg[0] = beta·inv2s`, `breg[l] = 2·breg[l-1]²`, all bound.
4. **NEXT: round-0 leaf fold (PBUF/SCR) + M_FHI higher-round fold** (column,
   deg 2, BREG now available) + **HIT** (= [VC == GPB]) + **RUNEV carry/update**
   + the **fold-leaf consistency** `CONSF·HIT·(v − RUNEV) == 0`.
5. **[X/XFIN DONE — Stage H; INVZ+INVZN DONE — Stages I/J]** reduced opening
   (M_RO), PZACC/PX accumulation (banks + inline ext) → RUNEV. Both inverses are
   now bound: INVZ (Stage I), and INVZN via the **ZN relation** `ZN = zeta·g_trace`
   pinned on query rows (Stage J) — no trailer selector needed; FA2 = fri_alpha²
   likewise. PZACC/PX is the big threaded accumulation `pzacc += preg·v;
   preg *= fri_alpha` over the trace/quotient openings + dup zeta values (inline
   ext-mul, deg 2) — still open.
6. **Final-poly Horn** (M_HORN) + the `RUNEV == final_eval` compare. Un-ignore
   `gate_neg_bad_fold`.

### Degree note

The header comment (module docstring) budgets **deg ≤ 5** for the fold pairs;
the column-based folds above are deg 2, but the bank-routed ladders/openings and
the phase automaton already put the rectangle at max degree 6 (see the
degree-budget section). Decide degree strategy (materialize vs. accept deg-5/6
quotient) together with the pre-existing degree-reduction item before benching.

### Key columns (all currently free witness)

VC (16), VCE, GPB (4), HIT, PBUF (4), SCR (8×4), BREG (4×4), PREG (4), PZACC (4),
A0R/A1R/A2R, P0R/P1R/PX0R, FPREG (16×4), INV2S/INVZ/INVZN, XREG/XFIN, RUNEV (4),
CONSZ/CONSF, ASM0/ASM1, CZ2/CZ7/CF/CX0/CX1/CZD (value-carry-row selectors),
POS (2). Witness fill: `write_row` (per row, pre-draw regs) + the value-capture
and micro-code blocks in the per-perm loop (`crates/qlab-bench/src/m4gate.rs`
~2140–2745). `scale()` maps native values to the R-homogeneous trace.
