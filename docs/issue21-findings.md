# Issue #21 — leaf-gate residuals: builder findings + implementation spec

Branch: `claude/issue21-leaf-residuals` (worktree `../qumbra-lab-issue21`).

## STATUS (updated)
- **R3 (FSGATE pin) — DONE** (commit 3a90aca). Full unfiltered suite green.
- **R1 (canonicity comparator) — DONE** (commit 80b578b). Self-contained approach
  (A) below: +34 gate-tail cols, GATE_WIDTH 3638→3672. Full unfiltered suite green
  (70 tests), deg≤3 held. Leaf b4/q40/g22 measured ×2 (zero swap): fixed
  **788.2 KB** (vs 781.8 KB baseline = **+6.4 KB / +0.82%**, all from R1's 34
  cols), prove 695/890 ms (grind jitter, ≪10 s), peak RSS 11.89 GB (≪32 GB,
  unchanged). 3672 cols × 2^16.
- **R2 (public-surface digest) — REMAINING.** Spec below. It is the residual that
  changes the public surface; coordinate with the stage-2 / 棒 3 merge-digest
  builder before implementing to avoid a double implementation at the leaf.

The rest of this doc is the original analysis (R1's non-obvious crux etc.), kept
for the record and for the R2 implementation.

All line numbers are against m4gate.rs at branch base (main @ 8298990).

---

## Ground-truth facts established by reading eval/fill

1. **`Val` = KoalaBear, P = 0x7F000001** (m4gate.rs:109). Ext = KoalaBear[x]/(x⁴−3).
2. **The routed words `W0C`/`W1C` are consumed ONLY in arithmetic** (pzacc/preg
   accumulation 3430–3452, fold `pbuf` 3236, Horner `fpreg` 3528). Grepping every
   `self.layout.w0c` / `self.layout.w1c` / `self.layout.asm0/1` reference in
   `eval` shows **no constraint binds them to the keccak preimage limbs
   `pcol(...)`**. They are semi-free witness columns whose only tie to the
   transcript is through the fold-endpoint value-pins (M_RO start / M_HORN end,
   added at the gate-exit milestone) plus the challenge registers.
3. **The canonicity columns `HB0/HB1/TA0/TOPA0/LBNZ*/LBI*/LONZ*/LOI*` are filled
   by `fill_canon` (4295) on every `casm` row but are never referenced in eval.**
   Confirmed by the inc-4 status doc §2.6 ("must be *added* as part of building
   the routed-word → asm → digest binding"). `fill_canon` even `assert!(w < P)`.
4. **`fill_canon`'s current column semantics** (per word, hi = w>>16):
   - `hb[0..16]` = bits of hi (word bits 16..31). So `hb[j]` = word bit `16+j`;
     `hb15` = word bit 31.
   - `ta`  = [(hi>>8)&0xf == 0xf]  = word bits 24..27 all set (**4-bit AND**).
   - `topa`= ta && [(hi>>12)&0x7 == 0x7] = word bits 24..30 all set (**7-bit AND**).
   - `lbnz`/`lbi` = [lb≠0]/inv, lb = hi&0xff = word bits 16..23.
   - `lonz`/`loi` = [lo≠0]/inv, lo = w&0xffff = word bits 0..15.
5. **Value-consuming rows** (`casm = czd + cz7 + cf`, defined 2900; plus the query
   PX rows cx0/cx1): `fill_canon` is called only under `casm` (4558–4561), NOT on
   cx0/cx1. czd (dup zeta values) and cz7 (final-poly) span **both direct (block 0)
   and XOR (block>0) keccak blocks** (block classification `lane_plan` 3752 /
   `is_xor,w_direct` 4411). cf (fold leaves) are direct-only.
6. **Draw-hosting perms = `consumersel`** exactly. `lane_plan` classifies obs-flush
   block-0 perms as `PInfo::Obs{block:0}`, refills AND the trailer as
   `PInfo::Refill` (3780/3805). In eval `consumersel = refsel + Σ_{f≥1} shsel(f,0)`
   (2464–2469) — the same set. `consumersel` is a per-perm 0/1 one-hot (constant
   across a perm's 24 rows in the challenger phase).
7. **The FS gadget's `limb_mux` (2660–2669) already pins each FS row to a specific
   digest limb** of the *current* perm: row r ⇒ limb g=7−⌊r/2⌋. So moving a draw
   to a different row of the *same* perm already breaks limb consistency.

---

## R1 — canonicity comparator (the crux is non-obvious)

### Why "just reference the columns" is wrong

`W0C` is a **field element**, always reduced: `Val::from_u64(w0v)` (4478) collapses
`v` and `v+p` to the same element `v`. So the alias the negative wants to inject
(`w+p`, same residue) **cannot be represented in the `W0C` column** — the column
holds `v` either way. A canonicity check therefore cannot operate on `W0C`-as-a-
field-value (every field value is trivially < p). It must operate on a **32-bit
integer decomposition** that is *range-forced* so that only genuine base-2^16
digit splits are admissible; canonicity then rejects the split whose integer ≥ p.

### The soundness requirement

To be a REAL constraint (not theater) the decomposition must be **bound to the
consumed word** so the prover cannot dodge with `hi=0, lo=v`. Two ways to bind:

- **(A) self-contained, to `W0C`:** constrain `W0C == Σ lo_bit[i]·2^i +
  2^16·Σ hb[i]·2^(i)` with `lo_bit[0..16]` and `hb[0..16]` all boolean. Because
  each half is a genuine 16-bit value, `hi·2^16+lo` is an integer in [0,2^32) that
  is ≡ v (mod p): exactly the canonical `v` and the alias `v+p` (and rarely `v+2p`).
  Canonicity forbids all but `v`. The negative fills `hb`/`lo_bit` with the
  `v+p` digits → the field equation still holds (v+p≡v) → the canonicity gate
  fires → UNSAT. **Cost: +32 lo-bit columns (16/word)** — `hi` bits already exist
  as `hb`.
- **(B) to the digest-bound keccak message limbs `pcol`:** the raw absorbed word
  (which CAN be v+p) lives in the 16-bit, keccak-range-checked preimage limbs.
  Bind `Σ hb == pcol(hi)` and `lo := pcol(lo)`. **0 lo-columns**, but the value
  rows span XOR blocks where the message = `pcol XOR prev_out` (recovered via the
  PBIT/OBIT bit columns, deg-2 per bit) — messy and per-block-type muxed.

**Recommendation: approach (A).** It is provably sound, uniform across
direct/XOR/query rows, verifiable with `check_constraints`, and independent of the
still-murky word↔pcol binding. The doc's "grinding-bit" motivation is about the
*consumed* word; (A) makes the consumed word's canonical representation the only
admissible one, which is the letter and spirit of "every consumed word carries an
explicit < p comparator."

### Exact deg≤3 constraint set (approach A), gated by `casm = czd+cz7+cf`

Per word (columns: existing `hb`, `lbnz/lbi`, `lonz/loi`; **new** `lo[0..16]`,
and **new** `top7` materialization):

```
// bit booleans (unconditional; off-casm rows must be zeroed by fill)
assert_bool(hb[i]), assert_bool(lo[i])                          for i in 0..16
// binding: consumed field value == the 32-bit digit split          (deg 2 w/ gate)
casm · (W0C − Σ lo[i]·2^i − Σ hb[i]·2^(16+i)) == 0
// low-part nonzero witnesses (lb = word bits 16..23 = hb[0..8])
lb  = Σ_{i<8} hb[i]·2^i ;  lb·lbi == lbnz ;  (1−lbnz)·lb == 0     // lbnz bool
loV = Σ_{i<16} lo[i]·2^i; loV·loi == lonz;  (1−lonz)·loV == 0     // lonz bool
// top-7 flag (word bits 24..30 all set) materialized at deg 3:
ta   == hb[8]·hb[9]·hb[10]                 // REDEFINE fill: was bits 24..27
topa == ta·hb[11]·hb[12]                   // REDEFINE fill: was bits 24..30
top7 == topa·hb[13]·hb[14]                 // NEW column
// canonicity (reject iff bit31 set, or top-7 set with low-24 nonzero):
casm · hb[15]        == 0
casm · top7 · lbnz   == 0
casm · top7 · lonz   == 0
```
All terms deg ≤ 3 (`casm` is a sum of three deg-1 selector columns; `top7`,
`lbnz`, `lonz` are deg-1 columns). `constraint_degree_within_budget` stays green.

### Column / layout surgery (approach A)

- New columns per word: `lo0[16]`, `lo1[16]`, `top7_0`, `top7_1` → **+34 columns**.
- Append them at the END of the gate block so no existing offset shifts: in
  `GateLayout::from_shape` (1210) after the wide-only merge lane (`dlr`, 1384),
  base = `cc + s.cap_len + merge_cols`; recompute `gate_cols`/`gate_width`. Mirror
  in the module const chain after `CC + CAP_LEN` (995–999) and add the four
  `assert_eq!` lines to `gate_layout_narrow_reproduces_consts` (~5924) and the
  struct field list (1389–1403).
- **Fixed-point ripple (expected, disclosed):** `GATE_WIDTH` is self-referential —
  the leaf verifies a wide proof of *its own* width `tw = GATE_WIDTH` (5757/5760).
  Growing it 3638 → 3672 changes `flush_bytes` F0/F2 (401/403), `n_opvs`, the
  recorded schedule (walk auto-adjusts), and any hardcoded "3638"/derived counts
  (e.g. 5967 docstring). This is the same operation prior sessions did
  (3532→3626→3638); the measurement note explicitly expects "small col adds, size
  delta small." Wide/interior suites recompute from the new width and must stay
  green.

### Negative `neg_noncanonical_word`

Pick a `casm` value row (dump via `dump_trace`/`dump_cols`), read its honest word
`v`, set `hb`/`lo` bit columns to the digits of `v+p` (and update `lbnz/lonz/ta/
topa/top7` to match `v+p`), leave `W0C` = `v` (unchanged; v+p≡v). Every other
constraint stays satisfied (the field binding equation still holds); the canonicity
gate fires. `assert_unsat` (6385).

---

## R2 — public-surface running-digest

- Outer PVs today: `N_OPVS = n_caps·cap_len·16 + n_pvs` (444), bound individually.
- Work: keccak-sponge the ordered PV list inside the lane and expose the digest as
  a public output. "Schedule slots exist — same mechanism as the existing digest
  closes" (issue) = reuse the f2dig/dup-style digest-capture machinery
  (2607–2619) on a dedicated block whose message IS the ordered PV stream, then
  expose the squeezed digest as new PVs and constrain `digest == that block's
  output`.
- **This is the one residual allowed to change the public surface** (prompt). It
  adds PVs → `N_OPVS`/`N_PVS` grow → the narrow leaf proof size changes; disclose
  before/after in the PR body.
- Acceptance: circuit-exposed digest == natively recomputed digest of the same PV
  list; tamper any single PV → UNSAT (the tamper changes the sponge input → the
  squeezed digest ≠ exposed PV). Coordinate with the stage-2 builder / 棒 3
  merge-digest (issue note) to avoid double-implementing at the leaf.

---

## R3 — FSGATE schedule-position pin

- **The row-within-perm is already pinned** by `limb_mux` (2669): each FS row must
  match a fixed digest limb, so moving a draw to a different row of the same perm
  already breaks limb consistency.
- **The genuine gap** (inc-4 status §"FSGATE position", 124/244): FSGATE can be
  spuriously activated on a **non-draw-hosting perm** (its preimage is message
  data, not a digest), relocating/injecting FS activity while staying locally
  consistent. Draw-hosting perms = `consumersel` (fact 6).
- **Pin (deg 2/3):**
  ```
  fs · (1 − consumersel) == 0                       // FSGATE only on host perms
  (1 − sf(23)) · nv(fsgate) · (1 − cv(fsgate)) == 0  // contiguous prefix from row 0
  ```
  `consumersel` is currently a local at 2464; recompute it (cheap) at the FS gadget
  (~2640) or hoist it. Contiguity is honest (draws fill rows 0..2k−1) and blocks
  gap-relocation that limb_mux alone might not (if a target row happens to read a
  matching limb).
  **CONFIRMED SAFE for the positive trace:** the trailer perm (which hosts the last
  flush's draws → FSGATE=1) is `PInfo::Refill` and the boundary handler sets
  `regs.refsel = true` for the next Refill (4941), with `phc` still 1 (it only
  drops at the Dup{block:0} entry, 4947). So `consumersel = 1` on the trailer and
  `fs·(1−consumersel)` holds everywhere FSGATE=1. Dup/Query perms have
  consumersel=0 and FSGATE=0.
  **Negative is the delicate part:** must be SAT on base branch and UNSAT only
  after the pin. Cleanest = a spurious FSGATE=1 on a non-consumer (Dup/Query) row
  with the byte-gadget columns crafted so fsodd/crot/grot/limb-consistency all
  still pass — only then does it isolate `fs·(1−consumersel)`. Budget iteration
  time (check_constraints).
- **Negative `neg_fs_row_moved`:** the surgical part. Cleanest is to activate
  FSGATE on one row of a NON-consumer perm crafted so all *other* constraints
  (fsodd/crot/grot/byte-gadget/limb) still pass — then only the new
  `fs·(1−consumersel)` fires. Alternatively move a real draw pair onto the trailer-
  adjacent perm. Budget the construction time; verify it is SAT on base branch and
  UNSAT only after the pin (guards against limb_mux already catching it — a
  should-fail-for-the-right-reason check).

---

## Sequencing recommendation for the implementation session

1. **R3 first** — constraint-only, no width ripple, lowest risk; banks a clean
   commit and exercises the schedule selectors. (Issue suggests R1 first for
   soundness priority, but R3 is the safer warm-up and independent.)
2. **R1** — the +34-column fixed-point ripple; do it in one commit, lean on the
   compiler + `gate_layout_narrow_reproduces_consts` + `check_constraints`.
3. **R2** — public-surface change; coordinate on double-impl; disclose size delta.
4. After all three: measure leaf b4/q40/g22 prove + fixed size ×2
   (`/usr/bin/time -l`, zero swap) vs the **781.8 KB** baseline (gate-exit was
   779.6 KB @ b4/q40 pre-issue#22; issue#22 moved to g22 — confirm the current
   baseline number by building base branch first).
5. Full unfiltered `cargo test --release -p qlab-bench` green at every commit
   (rule #5). Open PR, do NOT merge.

## Traps to remember
- deg≤3 is the HARD bar (the `constraint_degree_within_budget` guard), NOT the
  module-doc's "deg 5" prose.
- Off-`casm` rows must have the new bit columns zeroed or the unconditional
  `assert_bool` / `top7`-defining constraints fail; verify `write_row` zeroing.
- Do not touch `../qumbra-lab-mwhir`. `#24` (msh) touches m4gate.rs after this baton.
