# M4 step 1 stage 2 (棒 1b): wide-shape parameter derivation

Read-only investigation. **No circuit code changed; `git status` is clean.**
Scope: derive every shape-dependent width the leaf gate (`m4gate.rs`) still
carries as a narrow module `const`, verify each formula reproduces the narrow
value, then apply it to the **wide** inner-proof shape (a leaf `VerifierGateAir`
proof committed at `AGG_CFG` = b4/q40/g20/fp16/a16, 2^16 × 3,626).

All wide numbers below were **derived on paper first, then confirmed empirically**
by one `leaf_proof()` + `walk_leaf()` run (throwaway printing test, since removed).
Run cost: **peak RSS 11.88 GB, 4.45 s wall** (Apple M5 Max / 36 GiB; the b4 leaf
prove is fast, RAM is the cost — matches the task's "~12 GB" estimate).

## Shape parameters (from `GateShape`, m4gate.rs ~201)

| param | narrow | wide | source |
|---|---|---|---|
| `tw` (opened trace-row width) | 617 | 3626 | proof `trace_local.len()` |
| `qw` (quotient leaf base words) | 16 | 8 | quot leaf absorb |
| `n_pvs` (inner public values) | 84 | 852 (`N_OPVS`) | wide inner PVs = leaf's own opvs |
| `nq` (queries) | 20 | 40 | FRI config |
| `log_max` (index bits = inner deg_bits + log_blowup) | 22 | 18 | 18+4 vs 16+2 |
| `log_arities` | [4,4,4,2] | [4,4,4] | commit-phase steps |
| `cap_len` (= 2^cap_height) | 8 | 8 | cap_height 3 |

Derived: `n_fri_rounds = len(log_arities)` (narrow 4, wide 3);
`cap_height = log2(cap_len) = 3`; `cum = [0,4,8,12(,14)]`;
`path_levels[b] = log_max − cum_shift[b] − cap_height`, i.e.
narrow `[19,19,15,11,7,5]`, wide `[15,15,11,7,3]`
(trace, quotient, then one per fold round).

---

## 1. Formulas + narrow reproduction

### QSLOTS — per-query program length (perms/query)

The query program (`qprogram`, ~1152) walks, per query: the **trace** leaf+path,
the **quotient** leaf+path, and per fold round a **fold** leaf+path. Each leaf is
a keccak leaf-sponge (rate 34 u32 words/block → `ceil(words/34)` perms); each path
is one 2-to-1 compress per native Merkle level (`path_levels[b]`; the cap-extension
levels are in-circuit-only and dropped from the program):

```
leaf_words:  trace = tw            quot = qw            fold_r = 4·2^(la_r)   (ext=4 words each)
leaf_perms(n)= ceil(n/34)
QSLOTS = ceil(tw/34) + path_levels[0]          # trace  leaf + path
       + ceil(qw/34) + path_levels[1]          # quot   leaf + path
       + Σ_r [ ceil(4·2^(la_r)/34) + path_levels[2+r] ]   # fold rounds
```

Narrow: `ceil(617/34)=19` + 19 + `ceil(16/34)=1` + 19
+ [ (2+15)+(2+11)+(2+7)+(1+5) ] = 58 + 45 = **103 ✓** (= `QSLOTS`).
(Per round leaf: la=4 → `4·16=64`w → `ceil(64/34)=2`; la=2 → `4·4=16`w → 1.)

### N_SHAPES_OBS — obs-shape selectors (SHSEL width)

Each **observation** (Fiat-Shamir) flush contributes one shape selector **per
distinct challenger block mosaic** (`shsel_index`, ~2950; `shape_list`, ~456). All
flushes give one selector per block, **except** the big zeta-opening flush (obs
index 2), whose interior blocks are the uniform `F2Mid` mosaic (value words only),
so it collapses first/mid/last → 3 shapes:

```
N_SHAPES_OBS = Σ_obs_flushes  distinct_shapes(f)
distinct_shapes(f) = 3 if f is the zeta-opening flush and n_blocks(f) ≥ 3
                     else n_blocks(f)
```

Narrow: F0..F7 block counts `[5,3,148,3,3,3,3,3]`, F2 collapses 148→3:
`5+3+3+3+3+3+3+3 = 26 ✓` (= `N_SHAPES_OBS`). Total obs flushes = `4 + n_fri_rounds`
(alpha, zeta, fri_alpha, one per beta round, and the final-poly/PoW flush).

### FLUSH_BLOCKS / FLUSH_BYTES — challenger flush geometry

The obs stream is segmented by draws into `4 + n_fri_rounds` flushes. `FLUSH_BYTES`
is the pre-padding message length (**including** the 32-byte chain prefix for f>0);
`FLUSH_BLOCKS = FLUSH_BYTES/136 + 1` (keccak rate 136 B, `+1` for the always-present
10*1 pad — see `Transcript::flush`, ~465). Per-flush content (from the observe
sequence in `walk_with_cfg`, ~646):

| flush | content | bytes |
|---|---|---|
| F0 | deg_bits + base_deg + prep_width + trace cap + PVs | `12 + cap_len·32 + n_pvs·4` |
| F1 | chain + quotient cap | `32 + cap_len·32` |
| F2 | chain + trace@ζ + trace@ζ·g + quot@ζ (all ext, 16 B) | `32 + 16·(tw + tw + qw)` |
| F3..F(2+n_fri_rounds) | chain + FRI-round cap | `32 + cap_len·32` (=288) |
| final | chain + final_poly + log_arities + PoW witness | `32 + fp_len·16 + n_fri_rounds·4 + 4` |

`fp_len = 2^log_final_poly_len = 16`. Note **F2 content = 16·(opened-values/query)**;
`opened/query = 2·tw + qw` (local + next trace row + quotient) — this is the
stage-1 "7,260 opened values/query" for wide.

Narrow: F0 `12+256+336=604`; F1 `32+256=288`; F2 `32+16·1250=20032`;
F3..F6 `288`; F7 `32+256+16+4=308` → `[604,288,20032,288,288,288,288,308] ✓`.
Blocks `[5,3,148,3,3,3,3,3] ✓`.

### N_FHG — M_FHI higher-round fold gates

Folding an arity-`2^la` group to a scalar is `2^la − 1` binary-fold pairs; level 0
(`2^(la−1)` pairs) is the round-0 leaf fold (GF/BPM family), so the M_FHI family
handles the rest:

```
N_FHG = Σ_r ( 2^(la_r − 1) − 1 )
```

Narrow [4,4,4,2]: `7+7+7+1 = 22 ✓`. (This is **already** parametrized in
`GateLayout::from_shape`, ~870.)

### BREG width — per-level fold coefficients

`BREG` holds the binary-fold coefficient ladder for **one round at a time**, indexed
by fold **level** `l ∈ 0..max(la)` (the `for l in 0..4` loop at ~2487; 4 = max
levels of an arity-16 round), 4 ext limbs each:

```
BREG_width = max(log_arities) · 4
```

Narrow `max=4 → 16 ✓`. (The module comment "n_rounds×4" is a numeric coincidence
for narrow; the code indexes by fold **level**, not round.)

### DRND width — absorb-round selectors

Dparam codes T, Q, F0..F(n_fri_rounds−1) (`D_T=0, D_Q=1, D_F=[2,3,4,5]`):

```
DRND_width = 2 + n_fri_rounds
```

Narrow `2+4 = 6 ✓`.

---

## 2. Wide values

**All confirmed empirically** (leaf_proof + walk_leaf on the real wide proof):

| quantity | formula | **wide value** | narrow |
|---|---|---|---|
| **QSLOTS** | see §1 | **165** | 103 |
| **N_SHAPES_OBS** | Σ distinct block shapes | **46** | 26 |
| **FLUSH_BLOCKS** | 7 entries (4+n_fri_rounds obs flushes) | **[28, 3, 855, 3, 3, 3, 3]** | [5,3,148,3,3,3,3,3] |
| **FLUSH_BYTES** | " | **[3676, 288, 116192, 288, 288, 288, 304]** | [604,288,20032,288,288,288,288,308] |
| **N_FHG** | Σ(2^(la−1)−1) | **21** (7+7+7) | 22 |
| **BREG width** | max(la)·4 | **16** (unchanged) | 16 |
| **DRND width** | 2 + n_fri_rounds | **5** | 6 |

QSLOTS_wide breakdown (empirical, q0): trace leaf 107 (`ceil(3626/34)`) + trace
path 15; quot leaf 1 (`ceil(8/34)`) + quot path 15; fold leaves [2,2,2] + fold
paths [11,7,3] → `107+15 + 1+15 + (2+11)+(2+7)+(2+3) = 165`.

FLUSH details (empirical): F0 `12+256+3408=3676` (n_pvs=852 confirmed); F2
`32+16·(3626+3626+8)=32+16·7260=116192`; final `32+256+12+4=304`. Blocks:
`3676/136+1=28`, `116192/136+1=855`, `304/136+1=3`. There are additionally **5
refill flushes** (32-byte chained digest re-reads) hosting the 65 draws — these are
`Refill`-shape, not obs shapes, so they don't enter `N_SHAPES_OBS`.

Note: `N_SHAPES_OBS_wide = 46` follows the **current per-block scheme** (only F2's
interior collapses). Wide F0 grows 5→28 blocks almost entirely from the 852
public-value words; these are `Pv(idx)` mosaics carrying distinct indices, so they
do **not** collapse the way F2's index-free `Val` interior does. If 棒-1b wants to
shrink SHSEL it would need a new positional-Pv collapse; absent that, 46 is correct.

---

## 3. Refactor site list for 棒 1b (builder / trace code only)

Compile-time uses of **shape-varying** counts as array sizes / loop bounds in the
non-`eval`, non-`#[cfg(test)]` builder+trace path. (eval already reads most shape
via `self.shape.*`, but still uses the group/chal/role/micro module consts — noted
at the end.)

### Keyed on shape-varying counts — MUST become runtime

**`qprogram()` (~1152) — narrow-hardcoded generator, called by `build_gate_trace` + `VerifierGateAir::new`:**
- `1152` `fn qprogram() -> [u32; QSLOTS]` — return array size = QSLOTS
- `1155` trace leaf `F34 + 17×C34 + C5` — the `17` = `ceil(tw/34) − 2`
- `1183` `for r in 0..4` — **fold-round loop → n_fri_rounds**
- `1184` `if r < 3 {…F34+C30} else {…F16}` — leaf-block branch (really `4·2^la ≤ 34`)
- `1190` `PATH_LEVELS[2 + r]`, `1191` `CUM[r + 1]` — shape arrays
- `1193–1214` micro `match (r,l)` and `R_PLAST_F0..F3[r]` — round-keyed vocabulary
- `1216` `assert_eq!(p.len(), QSLOTS)`

**`gate_consts()` (~1274):**
- `1275` `two_adic_generator(LOG_MAX)`, `1276` `kx: [_;22]` (= `[_; log_max]`)
- `1277` `lf: [usize;4] = [18,14,10,8]` — per-round fold-path source heights (n_fri_rounds)
- `1278` `sk: from_fn(|r|…)` and `1282` `kf: from_fn(|r|…)` — `[Vec;4]` over rounds; use `LOG_ARITIES[r]`
- `1300` `g_trace = two_adic_generator(18)` — **hardcoded inner degree_bits; wide=16** (=`log_max − log_blowup`)

**`struct Regs` (~3174) / `Regs::new` (~3225):**
- `3195` `chal: [Ext; N_CHALS]` — N_CHALS (shape-varying, see below)
- `3198`/`3247` `idxr: [u32; NQ]` / `[0; NQ]` — NQ
- `3214` `scr: [Ext; 8]` — `2^(max_la − 1)` scratch pairs (=8 for a16)
- `3215` `breg: [Ext; 4]` — `max(la)` levels
- `3232` `qcnt: QSLOTS as u32`; `3234` `blkcnt: FLUSH_BLOCKS[0]`

**`lane_plan` (~3007):**
- `3021`/`3024` `FLUSH_BLOCKS[obs_ord]` / `FLUSH_BYTES[obs_ord]` asserts
- `3046` `assert_eq!(obs_ord, 8)` — **8 → 4 + n_fri_rounds (wide 7)**
- `3072` `for q in 0..NQ`; `3073` `for slot in 0..QSLOTS`; `3069` `qprogram()`

**`write_row` (~3283):**
- `3283` `program: &[u32; QSLOTS]` param; `3296` `for i in 0..QSLOTS`; `3297,3299` `% QSLOTS`
- `3326` `ring_at(qsel, NQ+1, …)`; `3338` `qsel < NQ`; `3344` `for k in 0..LOG_MAX`; `3409` `for q in 0..NQ`
- `3716` `LOG_ARITIES[rf]`, `3718,3721` `CUM[rf]` — fold-round

**`build_gate_trace` body (~3570):**
- `3577` `GateShape::narrow()` — **the core hardcode**; `3576` `qprogram()`; `3575` `gate_consts()`
- `3586` `assert_eq!(rows, 1<<16)` — wide interior needs ~8,360 native perms → **2^18** rectangle, not 2^16
- `3609` `chal_expect: [Ext; N_CHALS]` + `3613–3616` `sched.betas[0..3]` — assumes 4 betas
- `3687` `regs.pr_rot % QSLOTS`
- `4021` `CUM[rf+1]` + `lf=[18,14,10,8]`; `4037` `LOG_ARITIES[rf]` — fold-round
- `4142–4146` `% QSLOTS`, `QSLOTS`, `== NQ`; `4224` `qsel, NQ`; `4229` `for q in 0..NQ`
- `4310` `[Val::ZERO; N_FHG]`; `4311` `for rf in 0..4`; `4312` `if rf<3 {7} else {1}`; `4314` `fhg_index`
- `4343` `ring(qsel, NQ+1, NQ-1)`; `4346` `for f in 0..8` (**obs flushes, wide 7**); `4350` `FLUSH_BLOCKS[f]`
- `4397` `for f in 0..N_FHG`

**Shared eval+trace helper:**
- `fhg_index` (~1047) `rf*7+r` / `21` — hardcodes 7 pairs and last index; should be
  `Σ_{r'<rf}(2^(la_{r'}−1)−1) + r`, last `= n_fhg − 1`

### ⚠️ Correction to the task's "FIXED" list

Four of the counts the brief lists as **FIXED — leave alone** are in fact
**shape-varying** and MUST be converted for wide (verified against the code, not
assumed):

| const | narrow | formula | **wide** |
|---|---|---|---|
| `N_CHALS` | 7 | `3 + n_fri_rounds` | **6** |
| `N_GROUPS` | 29 | `5 + n_fri_rounds + nq` | **48** |
| `N_ROLES` | 13 | `9 + n_fri_rounds` (`R_PLAST_F*`) | **12** |
| `N_MICROS` | 18 | `6 + 3·n_fri_rounds` (`M_S/M_B/M_FHI` per round) | **15** |

`N_GROUPS` is unavoidable: the group ring assigns query `q` the slot `G_IDX0 + q`
(eval ~2043 `for q in 0..self.shape.nq`), so it needs `nq` idx slots — 40 for wide
won't fit 29. The derived anchors also move: `G_POW = 3 + n_fri_rounds` (wide 6),
`G_IDX0 = 4 + n_fri_rounds` (wide 7), `G_DONE = 4 + n_fri_rounds + nq` (wide 47).
`N_FLUSH_ENTRIES = 9` (= n_obs_flushes + 1) → wide 8. These consts are read in both
eval and trace, so both sides need them runtime.

### Genuinely FIXED (leave alone), confirmed

- `CAP_LEN = 8` (cap_height 3 both shapes)
- ext-limb `4`s — extension degree D=4 (`BinomialExtensionField<Val,4>`); every
  `for k in 0..4` / `i,j in 0..4` ext-arith loop
- keccak-lane structural: 24 rows/perm, 100 limbs, `NUM_KECCAK_COLS`, `pcol/ocol`
- final-poly length 16 (`fpreg: [Ext;16]`, `fpi`, `fp_len`) — fp16 both shapes
- `VC` width 16, `scr` 8 — `2^max_la` / `2^(max_la−1)`; fixed only while a16 holds
  (both shapes have `max_la = 4`), so treat as max-arity-derived if arity ever moves

---

## 4. `build_gate_trace` shape-parametrization sketch

`build_gate_trace(sched, inner_pvs, extra_capacity_bits)` (~3570) currently derives
the narrow shape internally:

```rust
let consts = gate_consts();              // narrow generators
let program = qprogram();                // [u32; QSLOTS=103]
let shape   = GateShape::narrow();       // <-- hardcode
let layout  = GateLayout::from_shape(&shape);
```

**Minimal change: add an explicit `shape: &GateShape` parameter.** The shape *could*
be inferred from `sched` (`nq = sched.queries.len()`, `log_arities = sched.log_arities`,
`tw` from a trace leaf / zeta group, `log_max` from the fold heights, `qw` from the
quot leaf), but passing it explicitly is cleaner and matches the call sites:
`m4treerec` already knows it (`GateShape::wide()` pairs with `AGG_CFG`). Then:

1. `gate_consts()` → `gate_consts_from_shape(shape)` (new: read `log_max`,
   `log_arities`, inner `degree_bits = log_max − log_blowup`, per-round `lf`).
2. `qprogram()` → `qprogram_from_shape(shape)` (new: the §1 program driven by
   `n_fri_rounds`, `path_levels`, `ceil(tw/34)`, `4·2^la`; returns `Vec<u32>` of
   length `QSLOTS(shape)`, not a fixed array).
3. `from_shape(narrow())` → `from_shape(shape)` — **already exists and correct**;
   but `from_shape` itself must first stop using the narrow module consts
   `QSLOTS`, `N_SHAPES_OBS`, `N_CHALS`, `N_GROUPS`, `N_ROLES`, `N_MICROS`, `NQ`,
   `LOG_MAX`, `FLUSH_BLOCKS` and compute them from `shape` (per §1–§3 formulas).
   `n_fhg` is already shape-derived there.
4. Internal narrow literals (§3 list): the `0..4`/`0..8` loops, `[…; NQ]`,
   `% QSLOTS`, `betas[0..3]`, `FLUSH_BLOCKS[f]`, and the `rows == 1<<16` assert must
   read `shape`/`sched` (and the rectangle height must grow — wide interior ≈ 8,360
   native perms → 2^18).
5. `VerifierGateAir::new_with_shape(shape)` (~1338) must use the **shape-parametrized**
   `qprogram_from_shape`/`gate_consts_from_shape` (today it still calls the narrow
   generators — that's why the doc-comment warns `from_shape(wide())` "is NOT yet
   trustworthy"). `fhg_index` must also become shape-aware.

**What `m4treerec` passes for the interior node:** today `leaf_proof()` builds the
*leaf* (narrow inner) via `build_gate_trace(&walk(&m3_proof), &pvs, 2)` +
`VerifierGateAir::new()`. The interior builder (stage 2) will instead:
`let wide_sched = walk_leaf(&leaf, &opvs);`
`let (trace, meta) = build_gate_trace(&wide_sched, &opvs, GateShape::wide(), log_blowup);`
`prove(&cfg, &VerifierGateAir::new_with_shape(GateShape::wide()), trace, &meta.opvs)`
— i.e. the wide `Schedule` from `walk_leaf` plus `GateShape::wide()` (n_pvs = 852,
the leaf's own opvs) as the passed shape.

---

### Appendix — how these were confirmed

One `leaf_proof()` + `walk_leaf()` (throwaway `#[test]` in `m4treerec`, removed;
tree clean). Printed flush geometry `[28,3,855,3,3,3,3]` / `[3676,288,116192,…,304]`,
`N_SHAPES_OBS=46`, per-query q0 structure summing to `QSLOTS=165`, `qw=8`,
zeta groups `[3626,3626,8]`, `opvs=852` — all matching the paper derivations.
Run: peak RSS 11.88 GB, 4.45 s wall (M5 Max / 36 GiB).
