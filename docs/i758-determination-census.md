# Lab #758: class-2 determination census of the consensus AIRs

[中文版](i758-determination-census-zh.md) · English is authoritative on technical detail.

> Author: qumbra-opus5.5 (Claude Code, Opus 5.5), for issue #758. The engine is `qlab-air::detaudit` (feature `audit`) and its bench front end is `qlab-bench detaudit`. **Run labels (R6…R19) name the audit's box runs** (Graviton r7g instances, one process per run under `/usr/bin/time -v`). Each figure below is copied from its run's output line.
>
> **Runs used pre-publication revisions of this engine.** The census engine (`qlab-air/src/detaudit*`) at the R16 revision is identical to this PR's apart from one assertion message; the bench adds the lane guard and a `DETAUDIT_CONFIRM_COL` confirm filter (R18c only). Line numbers cited for `l2p.rs` and other files are this PR's.

> **Dated note, 2026-10-06 (lab #896 seam T). The verdicts below stand as of R16; this records what changed since.**
>
> 1. **P3 house, with every public value an output (`--no-pv-inputs --cr-premise`, the setting of §2's P3 house figure), now has 28 undetermined public values, not the four in §0/§2.** The four are still there: each row's `redeem` and `vpa` while its amount is 0. The 24 new ones are the fee, row 1's amount and the exit recipient. All 24 come from one enumeration group the engine skips for size: the per-row constraints of P's asset-0 exit edge, added by F5-4d (lab PR #797) after R16. The group is the same on v1 and v2. Under the codec premise of §3, all 28 are determined (measured on `p3v2`, whose group is the same).
> 2. **Candidate A (`s3v2`, `p3v2`, `rv2`, lab #896) adds no undetermined public value beyond v1's under the same premise set.** The v2 runs also take each slot's authorization-leaf public values as verifier-supplied, because the node fills them from the transaction's auth section. Under the codec and collision-resistance premises, S, P and R have 0 undetermined public values. With every public value an output, `p3v2` has the same 28 as v1.
> 3. **Engine since R16:**
>    - lab PR #918: a confirm's budget is enforced inside each pin and replay, not only between attempts;
>    - lab PR #919: enumeration admits wider groups with few booleans, and the skipped-group log prints the real boolean count instead of a hard-coded 0.
>
>    On v1 P3 house, both are determination-neutral: the old and new engines give the same result cell for cell. Neither decides the exit-edge group above.

## 0. Summary

Every verdict below cites the **R16 closing sweep**: runs R16a–d, every run `--confirm`, budget 900 (S3 merge 1500), every exit 0. The one exception is the P3 merge-with-vPublic row, which cites R17 and R18: the same engine, with two added fixtures.

| AIR | fixtures | verdict (R16) |
|---|---|---|
| claim | house, pathbits, fee0, feeall | **0 flags, 0 public values undetermined** on all four |
| narrow (L1) | house, dummy1 | **0 flags, 0 public values undetermined** |
| R (registry write) | house (update), register | **0 flags, 0 public values undetermined** |
| S3 | house | **0 flags, 0 public values undetermined** |
| S3 | merge | 0 public values undetermined. 2 flags, both **SAT with PVs moved []** (p3 SAT): the designed `q = 1` accounting freedom |
| P3 | house | public values undetermined **[100, 105, 106, 111]** = the codec-pinned pair of both (zero-amount) rows. Enumeration: the solutions differ in **[106, 111]** only; the amount agrees at 0 |
| P3 | mint, redeem (70,000 of asset 7, both signs) | public values undetermined **[100, 105]** (row 1's codec pair). Row 2's amount and sign are **determined** |
| P3 | merge (`--pin-sel2`) | **[100, 105, 111]**. Row 1's amount agrees at 0; the solutions differ in [100, 105] only |
| P3 | merge-mint (vPublic₁ = mint 70,000), merge-redeem (redeem 20,000); `q = 1` with vPublic₁ | the amount is **determined** given `o1a`/`o2a` (R17 `--pin-sel2`: `unique` at row 771,071, PVs undetermined [111]). The `o2a` flip is **SAT with PVs moved []** (R17). The `o1a` flip is **SAT with PVs moved []**, and p3 SAT (R18a/b). Plus the algebraic argument (§2 P3.6) |

P3 runs under the premises of §3 (the codec pair, collision resistance). Its remaining flags reach **no public value**.

**No open item remains on any AIR.**

**No run produced a SAT forgery that moves a public value on a real AIR.** The only SAT-with-a-public-value-moved results are the calibration and the blind plants (§1), which are the instrument catching what it was built to catch.

**The audit did find freedoms: satisfying changes of the witness that move no public value.** Each is classified, with its confirm:
- **S3 merge, `o1a`/`o2a`** (the output-row assignment under `q = 1`): confirmed SAT, PVs moved [], p3 check SAT. This is the designed accounting freedom. The balance closes on `BL + BL2`.
- **P3 bit-serial compare, T-row cells** (both blocks, every role): confirmed SAT, PVs moved [], p3 check SAT, 8 of 8 sampled. The compare's verdict is read only at `AFRZ`'s z = 63. **Designed malleability.**
- **P3 merge, the same `o1a`/`o2a` freedom,** including with a nonzero vPublic₁: `o2a` confirmed SAT with PVs moved [] (R14 flag 3; R17a/b flag 3); `o1a` confirmed SAT with PVs moved [] (R18a/b: 2,232,336 and 1,640,502 cells moved), and p3 SAT.
- **The P3 codec-pinned pair** (`redeem`/`vpa` on a zero-amount row) is free in the AIR and pinned by the surface codec (§3.2).
- **Post-END padding (P3, ep = 0):** hash-constrained only, reaching no public value (§4).

## 1. Method and calibration

**The question.** Is every cell of an honest trace, and every public value, a function of the witness manifest's inputs (the "sources")? A cell the constraints leave free is a class-2 freedom. It matters when it reaches a public value.

**The engine** (`qlab-air::detaudit`, feature `audit`) works in layers:

- **L2, the census:** a forward fixpoint from the sources.
  - Rules: affine with a nonzero coefficient; the unique root of a boolean; superincreasing recomposition over bounded variables; and the *extremal* sum (same-sign coefficients, target at 0 or at the maximum).
  - A boolean case split: two dependents, the same root under both values of the boolean.
  - Linear elimination: aliases, small systems, and 200-class neighbourhoods seeded at bounded-unknown equations.
  - **Bounded enumeration** (R11): per row, groups of stalled equations that read a public value and hold ≤ 12 boolean unknowns get every boolean assignment tried. The other unknowns are solved per case, and the in-range solutions are counted. A unique solution determines the group; two or more are logged as `AMBIGUOUS`, together with the differing public values.
  - Witness copies must be re-derived through their ties.
  - Late-determined public values re-open their readers.
- **L3, the confirm:** the undetermined cells are grouped into components. Each component's root is found by a single-cell ranking, then the root is flipped and its cone replayed (retried with the ties re-solved), with the other roots held.
  - **SAT is checked independently by p3's `check_constraints` on the full repaired trace.**
  - **Only a SAT is evidence.** An UNSAT with other roots held is not a refutation.
- **L1, the static role census** (orientation, and the reader of each consumed cell), plus **vacuity**: constraints that are neither load-bearing nor restricting on the audited trace.

**Calibration:**
- A known historical defect was re-introduced into one AIR and the census caught it: `SAT`, the public value moved, and p3's independent check agreed. **Calibration: planted-defect catch = yes.**
- Three **blind plants** were placed by the coordinator without telling the builder:
  - plant 1 on claim: caught, SAT, public values moved;
  - plant 2 on claim: caught, SAT, public values moved;
  - plant 3 on narrow: caught (flagged, root named). Its confirm didn't finish on a 43M-cell component, which is a recorded limit (§4).
- The toy rig (`--toy`, plus `--sign-top` / `--sign-wrap` for the enumeration) runs locally as the self-test.
- Unit tests pin the controls: `detaudit_rig_*` and `detaudit_sign_chain_enumeration`. They run on the lane.

## 2. Per-AIR verdicts (R16)

Each figure is copied from the run's output: wall-clock time, peak RSS (`/usr/bin/time`) and exit status.

| run | cells | determined | public values undetermined | flags | confirms | wall | peak kB |
|---|---|---|---|---|---|---|---|
| claim house | 85,852,160 | 82,728,489 | 0 | 0 | — | 2:39.46 | 3,633,548 |
| claim pathbits | 85,852,160 | 82,728,489 | 0 | 0 | — | 2:39.26 | 3,633,480 |
| claim fee0 | 85,852,160 | 82,728,489 | 0 | 0 | — | 2:39.46 | 3,633,480 |
| claim feeall | 85,852,160 | 82,728,489 | 0 | 0 | — | 2:39.38 | 3,633,480 |
| narrow house | 168,558,592 | 163,084,713 | 0 | 0 | — | 5:26.05 | 5,803,144 |
| narrow dummy1 | 168,558,592 | 163,084,713 | 0 | 0 | — | 5:26.47 | 5,803,256 |
| R house | 192,413,696 | 186,295,017 | 0 | 0 | — | 19:17.05 | 6,695,404 |
| R register | 192,413,696 | 186,032,873 | 0 | 0 | — | 19:14.83 | 6,733,696 |
| S3 house | 378,011,648 | 362,042,290 | 0 | 0 | — | 12:47.95 | 11,420,876 |
| S3 merge | 378,011,648 | 359,824,179 | 0 | 2 | `col692@role1` and `col693@role1` (`o1a`/`o2a`): **SAT, PVs moved []** | 27:32.90 | 12,869,520 |
| P3 house¹ | 836,763,648 | 773,627,356 | [100, 105, 106, 111] | 1,040,434 | 8 sampled: 7 UNSAT (PVs []), 1 SAT with PVs [] (`col562@role8`, the W lane of a compare row) | 1:36:29 | 28,291,660 |
| P3 merge¹ ² | 836,763,648 | 771,529,382 | [100, 105, 111] | 1,040,439 | 8: 6 UNSAT, 2 SAT with PVs [] (compare rows, role 8) | 1:45:40 | 28,189,520 |
| P3 mint¹ | 836,763,648 | 774,675,959 | [100, 105] | 1,040,434 | as house | 1:35:03 | 28,289,800 |
| P3 redeem¹ | 836,763,648 | 774,675,997 | [100, 105] | 1,040,434 | as house | 1:35:05 | 28,301,096 |

¹ `--no-pv-inputs --cr-premise` (§3.3). ² With `--pin-sel2` added (the diagnostic of §3.4, whose restriction is covered by the o1a/o2a flip being SAT with PVs [], R14 flag 3).

**P3's flags are almost all the ~1M one-row compare-row pieces:** the W lanes and `CMP_OFF…` on rows where only the bit-serial compare reads them. **None reaches a public value.** P3's enumeration at the balance close (row 771,071):
- **house:** `2 in-range solutions — differing: [106, 111]; agreeing: [107=0, 108=0, 109=0, 110=0]`;
- **merge:** `differing: [100, 105]; agreeing: [101=0, 102=0, 103=0, 104=0]`;
- **mint and redeem:** row 2 determined (`vPublic row 2: redeem determined | amount chunks undetermined [] | vpa determined`).

**Copy reads on the absorbing rows (P3, every fixture):** nk@ARKM′/″ 0/1536, ρ@ACMF 0/256, output ρ 0/512, nf1 0/256. nk@ARKM **256/1024 in perm [257]** and ρ@ACM **256/768 in perm [322]**, both printed `(all in the ep = 0 second pass)`.

### 2.L L1 (static) counts per AIR (R19)

L1 is the static role census. On sampled rows of each role, it flags a cell that some constraint consumes but no constraint in that role defines in orientation form `[gate·](X − expr)`. It **over-approximates by design**: it can't see a definition that's two-sided (a gadget), remote (pinned in another role and carried by a constancy transition), or absent because the cell is a designed free choice. Every L1 flag is classified below against the L2/L3 result that covers it. **None is unknown.**

| AIR | L1 flags | roles sampled | consumed / defined | wall | peak |
|---|---:|---:|---|---|---|
| narrow | **0** | 15 | 8,948 / 9,295 | 9.0 s | 667 MB |
| claim | **0** | 11 | 6,740 / 6,960 | 5.4 s | 344 MB |
| S3 | **4** | 19 | 12,279 / 12,945 | 18.4 s | 1.49 GB |
| P3 | **315** | 25 | 17,766 / 18,974 | 37.8 s | 3.28 GB |
| R | **1** | 21 | 14,332 / 14,789 | 11.6 s | 761 MB |

Column names are computed from each AIR's constant chain (`l2p`: `W_OFF` 560, `SEL2_OFF` 725, `CMP_OFF` 755, `POL_OFF` 777; `l2r`: `BGC_OFF` 550, `MC_COL` 726, `DR_COL` 730). The inline `// NNN` offset comments in `l2.rs`/`l2p.rs` had gone stale since A4; this PR recomputes them from the constant chain and pins the named offsets by test.

- **S3, 4:** the output-row selectors `o1a` (col 692, at BAL), `o2a` (col 693, at ACMOUT and BAL) and `q` (col 695, at BAL). Their readers are the close's asset-agreement definers, the `SG` definer and the `CQ` definer.
  - **Why L1 flags them:** they're witness **choices** with no orientation definer. `q` is forced by the two-sided asset agreement (`close_q·(ac₁ − ac₂)`, `close_nq·(QINV·(ac₁ − ac₂) − 1)`), and `o1a`/`o2a` by the per-branch asset agreement.
  - **Covered by:** R16 S3 house (0 flags: forced when the assets differ), and S3 merge (the `o1a`/`o2a` flips are SAT with PVs moved []: the designed `q = 1` accounting freedom).
- **P3, 315, in four groups:**
  - **136 = the W lanes `W0..W3` and `W5..W8`** (cols 560–563, 565–568, on sampled rows across the roles), read by the compare's seed constraints. `W4` isn't among them, and it's exactly the lane the compare doesn't read. On non-absorbing M rows, W is read **only** by the bit-serial compare. **Designed compare-row freedom.** Covered by R6b's 8/8 and R16's compare-row confirms (SAT with PVs [], p3 SAT).
  - **150 = the compare's running `LT` flags, lanes 1–3 of both blocks** (cols 756–758 and 767–769, 25 roles each), read by the lane-combine constraints `C1..C3`. They're free on T rows by design ("T rows are unconstrained"; the verdict is read only at `AFRZ`'s z = 63). The same compare-row class, and the same confirms.
  - **25 = `RG₀`** (`POL_OFF + 2`, col 779, every role), read on every row by constraint c662, a per-row consumer of `RG₀` (its reader line in R19's output). It's **pinned remotely**: bound to the registry leaf's mode bits at `AREG` (`AG_R1` gate), and carried to every row by `next[POL] = POL` (l2p.rs:1463). L1 checks per role and doesn't follow a cross-role constancy transition. Covered by L2: `RG₀` is determined in every R16 P3 run.
  - **4 = `o1a`/`o2a`/`q`** (cols 725, 726, 728; at BAL, plus `o2a` at ACMOUT). These are S3's four. Covered by R16 P3 house/mint/redeem (forced) and P3 merge, merge-mint and merge-redeem (the flips are SAT with PVs moved []: R14 flag 3, R17 flag 3, R18a/b).
- **R, 1:** `DR = [mode = Regulated]` (col 730) at `BREG_NEW`, read by the new-leaf mode definer (`MC`, col 726, gated by `BGC_BREG_NEW`). `DR` is an **is-zero indicator**, two-sided with its inverse witness `RINV`, which L1 doesn't read as a definer. Covered by R16 R house/register: 0 flags, `DR` determined.

**The lane guard pins exactly these counts** (0/0/4/315/1). A change in any of them fails the guard and must be re-classified here.

### P3: how the verdict was reached (R8 → R15)
The run sequence was R8 → R15, and it established the verdict in steps:

1. **Compare-row malleability.** About 1M one-row flags on the bit-serial compare's free T-row cells (`CMP_OFF…`). They're confirmed SAT with no public value moved (R6b, 8 of 8). **Designed.**
2. **vPublic, no inflation.**
   - With every public value an output (`--no-pv-inputs`), house's undetermined vPublic values are exactly **[100, 105, 106, 111]**, i.e. each row's `redeem` and `vpa` while its amount is 0 (R11).
   - **mint** and **redeem** (70,000 of asset 7, spanning two 16-bit chunks, both signs): `unique: row 771071 (7 eqs, 11 bools) PVs [106..111]`. Row 2 reads `redeem determined | amount chunks undetermined [] | vpa determined` (R13).
   - `--confirm-pv 107`: 0 flags reach it.
   - **The amount and sign are uniquely determined by the witness.**
3. **Anchor and cm.** Without the collision-resistance premise, the census stalls at the first `ARKM′`: row 141,312 = perm 46. `ARKM′`/`ARKM″` take `nk` as a free input bound only through their output (§3), so everything downstream reads free.
   - **With `--cr-premise`:**
     - house: undetermined = **[100, 105, 106, 111]**;
     - mint and redeem: **[100, 105]** (R14).
   - The anchor and cm are **determined**.
   - The flags that remain reach **no public value**:
     - the post-END padding (§4);
     - 975-cell W+compare pieces.
4. **Binding probes** (`--probe-arkm2`, R14). A copy on its absorbing row is flipped and its cone replayed. **Every copy is refused: no `NOT TIED`, no SAT.** Attribution:

   | copy | probe (first violations) | lane test (binding rows) | attributed to its binding |
   |---|---|---|---|
   | nk@ARKM′ | refused at ACRED rows (hash constraints at the junction with the EQ3-determined `rkm′`) | `l2p_neg_rkm_rederivation_lie` | by the lane |
   | nk@ARKM″ | refused at ACM rows (junction with the bind bank) | `l2p_neg_rkm_rederivation_lie` | by the lane |
   | nk@ARKM, input 0 | determined with the holes pinned | — | tie solved by the census |
   | nk@ARKM, fee chain | **bank 1's accumulator transition** (c1280), on the flipped row | `l2p_neg_bank_bound_copies` (bank-1 close rows) | ✔ probe + lane |
   | ρ@ACM | **bank 2's accumulator transition** (c1281, col591′) | `l2p_neg_bank_bound_copies` (bank-2 close rows) | ✔ probe + lane |
   | ρ@ACMF | same-row readers only in the first six | `l2p_neg_bank_bound_copies` (bank-2 close rows) | by the lane |
   | output ρ@ACMOUT | same-row readers, plus c1264 (col693′) | S10 and the dummy-shape forged seed (forgery shape) | by the lane |
   | nf1@ARHO | same-row readers only in the first six | `l2p_neg_bank_bound_copies` (third-bank close rows; cm2 unchanged, so the tamper is forgery-shaped) | by the lane |

   The lane tests run on this PR's lane (§5).
5. **merge.** Under `q = 1`, row 1's chain reads only `BL + BL2`, and BL/BL2 are individually free (the accounting freedom: R14 flag 3, `col726@role1`, SAT with **PVs moved []**). So the enumeration can't isolate row 1's amount (R14, undecided).
   - **The argument:** m₁ reads only the sum, and no `o1a`/`o2a` assignment changes the sum.
   - **Closed (R15; R16):** under `--pin-sel2` the enumeration at row 771,071 has 2 solutions `differing: [100, 105]; agreeing: [101=0, 102=0, 103=0, 104=0]`, and PVs undetermined [100, 105, 111]. Row 1's amount is determined. The pin only restricts, and the unpinned `o1a`/`o2a` flips move no PV (R14 flag 3; R17/R18 for the vPublic case).
6. **Merge with a nonzero vPublic₁ (`q = 1`: `merge-mint` 70,000, `merge-redeem` 20,000).**
   - **Reachability:** since A4's dedicated fee slot, `q = 1` is reachable on a policy asset (the merge). vPublic₁ is legal on the summed chain (l2p.rs:1180–1183), and the codec doesn't know `q`. The pre-A4 test comment claiming otherwise is corrected in this PR.
   - **R17:**
     - With `--pin-sel2`, both fixtures give `unique: row 771071 (7 eqs, 11 bools) PVs [100..105]`, PVs undetermined [111], and row 1 `redeem determined | amount chunks undetermined [] | vpa determined`. **The amount is determined given `o1a`/`o2a`.**
     - Without the pin, `o2a` (col 726) confirms **SAT, PVs moved [], p3 SAT**.
     - Also without the pin, `o1a` (col 725) sits in a component with row 1's policy cells and reaches 100..105. Its confirm was stopped by the budget.
   - **The o1a argument (checked independently in review):**
     - **Everything that reads `o1a`:** its booleanity (1034), `SG₀ = AG_O1·o1a` (1042–1045), the selectors' constancy transition, and the close's asset agreement `close·o1a·(ac(O1) − ac(IN1))` and `close·(1 − o1a)·(ac(O1) − ac(IN2))` (1236–1238).
     - **The sum cancels it.** The transitions `next BL_j = BL_j + AG_IN1·pw·v − SG₀·pw·v − SG₁·pw·v` and `next BL2_j = BL2_j + AG_IN2·pw·v − (AG_O1 − SG₀)·pw·v − (AG_O2 − SG₁)·pw·v` (1415–1436) sum to `(AG_IN1 + AG_IN2 − AG_O1 − AG_O2)·pw·v`. **`SG₀`/`SG₁` cancel**, and with the row-0 pins (1001–1004), `BL + BL2` is `o1a`-free on every row.
     - **Only the summed chain is live under `q`.** `CQ = close·q / close·(1−q)` (1036–1040). The two per-row chains are gated `close_nq` (0 under `q`); the third reads only `summed = BL + BL2` (1200, 1203–1213). `q` is forced both ways (1230, 1232).
     - **The asset agreement is branch-equal under `q`,** because `close_q` forces `ac(IN1) = ac(IN2)` (1230).
     - ⇒ Flipping `o1a` changes `BL`/`BL2` individually, and nothing that reads the amount, the sign, `vpa` or any other public value. The census's `o1a`+POL component is the sum-only engine gap joining through the undetermined m₁. **No `o1a`–POL constraint exists.**
   - **R18 (the `o1a` confirm).** Result: **SAT, PVs moved [], p3 SAT**, exactly as predicted. The untargeted ranking landed on column 725 itself.
     - **R18a** (merge-mint, budget 14,400): `confirm col725@role1 … (2232335 replayed, cone, 2232336 cells moved): SAT — PVs moved []`; `independent p3 … SAT`. 56:25.77 wall-clock, peak 28,000,056 kB.
     - **R18b** (merge-redeem): `1640502 cells moved: SAT — PVs moved []`; p3 SAT. 55:37.22, 27,956,360 kB.
     - **R18c** (forced `DETAUDIT_CONFIRM_COL=725`, merge-mint): identical to R18a. Its redeem half was stopped as a duplicate of R18b.
   - **R17 figures:**
     - merge-mint `--pin-sel2`: 44:45.58, 25,443,248 kB;
     - merge-mint no-pin: 1:48:12, 28,289,908 kB;
     - merge-redeem `--pin-sel2`: 45:33.19, 25,443,400 kB;
     - merge-redeem no-pin: 1:51:43, 28,287,188 kB.
   - **Verdict: closed.** The amount is determined given the accounting selectors, and neither selector's flip moves a public value.
7. **Crash fixed.** The affine replay divided by a vanished coefficient under perturbation (R14: `Tried to invert zero`). It is fixed in this PR; R15's second run exercised the fix.

## 3. Premises (every one printed by the runs that use it)

1. **Public-value ranges** (`audit_pv_bits`): every public value is a 16-bit chunk, except P3's `redeem` (1 bit), `vpa` (32 bits) and R's asset (32 bits). This is the verifier's own construction (`pv_chunks`/`pv_vec*`), and `qlab_l2::verify_*` and claim refuse a vector outside it (`pv_in_range`, `ClaimRefusal::PvRange`; lane test `l2_pv_range_premise_holds_and_is_enforced`). **The L1 frozen entry is to be narrowed** (follow-up PR).
2. **P3 zero-amount vPublic pair** (`l2p::audit_pv_inputs`): when a row's amount is 0, its `redeem` and `vpa` are declared inputs.
   - `qlab-devnet/src/annulet.rs:233` refuses `amount == 0 && (redeem || asset != 0)` (`NonCanonicalZeroTerm`) before any proof is checked.
   - **Paths:** the only consensus path that builds P3's public values is `qumbra-node/src/verifier.rs:123` (`L2Surface::decode(&entry.l2)`, where `TxEntry.l2: Vec<u8>`), then line 181 `pv_vec_p` from the decoded terms.
   - `qlab_l2::verify_p` itself takes raw public values and does **not** apply canonicality. Its other callers are bench and tests only. Any future caller that bypasses the decode loses the zero-term pin.
   - The amount chunks are never declared.
3. **Collision resistance** (`l2p::audit_cr_premise`): `nk` at `ARKM′`/`ARKM″` is declared a source.
   - It's bound only through its output: `rkm@AFKEY − rkm′@ACRED` on the third bank (closed at ACRED's end), and `rkm′@ACRED − rkm″@ACM` on the bind bank (closed at ACM's end).
   - A different `nk` reaching the same `rkm` is a Keccak preimage/collision, which is outside the census's algebraic scope.
   - Every other copy is tied by a bank to a value computed forward, and is **not** under this premise.
4. **Diagnostic premises.** Each is marked `⚠️ DIAGNOSTIC` in its output.
   - **`--pin-cmp`** (the compare's cells declared sources): **used for no verdict.**
   - **`--pin-sel2`** (the output-row selectors `o1a`/`o2a` declared sources): used for the P3 merge rows **only jointly** with the confirmed **unpinned** flips of exactly those selectors: `o2a` (R14 flag 3, R17a/b flag 3) and `o1a` (R18a/b), each **SAT with PVs moved []**, with p3's independent check SAT.
     - **Why the pair is sufficient:** the pin fixes two selectors at their honest values, and under it every public value is determined. The flips show that the other value of each selector also gives a satisfying witness, with **identical** public values. So no choice of the selectors reaches a different public value, and the pinned determination holds for every witness.
     - The algebraic argument in §2 P3.6 (the `BL + BL2` transition is selector-free; only the summed chain is live under `q`) says the same thing from the constraints.

## 4. Limitations and coverage

- **Post-END padding (P3, ep = 0).** `ep` is forced:
  - row-0 pin `EP = 1` (l2p.rs:894);
  - `next[EP] = EP·(1 − GWRAP)` (1386–1389);
  - `GWRAP = gperm·sel_role(12)` (895–898), where `SEL_CODES[12] = ROLE_END`;
  - the roles are decoded from a program ring pinned at row 0 to the AIR's own program (670–675), which rotates only by the fixed `g4` (1332–1336).
  - So `ep` = 1 through END's last row (slot 251) and 0 after it. The 2^20 trace repeats the program mod 252 slots past that point.
  - Every public-value read is killed at `ep = 0` (the table in §B), **except** the per-row vPublic consistency block (l2p.rs:1086–1103). That block restricts the padding's policy cells and can't free a public value.
  - **Not read line by line:** the blast/PB ring beyond its first-row pins.
  - Wording: "rows past END: hash-constrained only; no bank, bind or balance constraint is live there".
  - **Shown (R16):** the remaining undetermined absorbing copies are one perm each in that second pass. nk@4 256/1024 is in perm [257] and ρ@5 256/768 in perm [322], both printed `(all in the ep = 0 second pass)`.
- **dv = 1 modes on S3/P3** aren't exercised as the binding constraint: c638/c639 on S3 and c804/c805 on P3 are *live but not exercised as the binding constraint on the audited fixtures*.
- **P3 vPublic coverage.**
  - **Covered:**
    - mint and redeem on a Hybrid, closed asset with the issuer key, on row 2 under `q = 0` (mint/redeem);
    - on row 1 under `q = 1` (merge-mint/merge-redeem).
  - **Not exercised by the census,** each reachable and canonical (each is a satisfying instance in the AIR's own lane tests):
    - **vPublic on row 1 under `q = 0`** (two distinct policy-asset inputs, with a row-1 term): `l2p_vpublic_edges_satisfy` ("both rows carrying a term (two policy assets)");
    - **a `redeem_open` redeem without the issuer key:** `l2p_vpublic_edges_satisfy`;
    - **Regulated (the allowlist on):** `l2p_regulated_inputs_satisfy`.
  - Their balance chains are the same per-row chains the census did exercise (row 1's chain is row 2's with `f1`), but that's an argument, not a run.
- **A large-component confirm limit:** blind plant 3 was flagged but its 43M-cell component didn't confirm within budget.
- **L2b** (the full binding census) is budget-stopped, with 0 probes. The targeted probes (§2 P3.4) and the lane negatives replace it.
- **Engine versions:** every verdict cites R16, one engine revision. The earlier runs used older engines; the enumeration and case-split rules added since only add determinations, and R16 reproduces every earlier clean result.
- **Vacuity intersections** (R7): narrow 25–26, claim 27, R 49–54, S3 51–52, P3 66–88 constraints vacuous per fixture. The accepted uncovered modes are listed above. None is called "redundant" or "removable".

## 5. Lane evidence (runs with the #758 PR)

- `l2p_neg_bank_bound_copies`: row-level refusal at each binding's rows, with the honest trace clean on those rows first. **The added lane-minutes are to be measured**; if they exceed ~5, share one generated trace.
- `detaudit_rig_*` and `detaudit_sign_chain_enumeration`: the engine's controls.
- `l2_pv_range_premise_holds_and_is_enforced` and `l1_verify_path_builds_only_16_bit_public_values`: premise 1.
- **The resident lane guard** (`qlab-bench` `detaudit::lane_guard`), counts only: `detaudit_lane_guard_l1_counts` pins L1 flags on [narrow, claim, S3, P3, R] = [0, 0, 4, 315, 1] (§2.L), and `detaudit_lane_guard_claim_l2` pins claim's L2 at 0 flags and 0 public values undetermined. [P] cost ≈ 82 s + 2:42 on the lane's instance class.
- `l2_named_offsets_are_the_constant_chain` and `l2p_named_offsets_are_the_constant_chain`: the offsets §2.L names, pinned (the `// NNN` comments were stale since A4 and are recomputed in this PR).

## §B: the public-value read table (P3; `l2p.rs` line numbers are this PR's)
| lines | constraint | ep factor |
|---|---|---|
| 943–953 | digest binds `BGC_x·(BQ − pv·ep)` | the public-value term ·ep |
| 978–985 | `EG3+2·(EQ3 − (1−OM)·pv(nf1)·ep)` | gate `gperm·SE_RHO`, SE = sel·ep |
| 1215–1228 | the balance chains | gate `close`/`CQ` (= `gperm·SE[5]`·…) |
| 1250–1254 | the fee bank | `close` |
| 1263–1272 | the vPublic surface | `close`/`close_q` |
| 1086–1103 | nz / vpinv / cloaked / REQ | **ungated; restricting only** |

