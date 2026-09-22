# W3 — builder working notes (baton 1: stages 0 + 1)

Per-baton build notes for lab issue [#700](https://github.com/qumbra-labs/qumbra-lab/issues/700)
(W3 — the L2 circuit family, shapes S and P, measured). **Not paired** (CLAUDE.md: build notes
are written by a session for a session). Branch `claude/w3-l2-shapes`, worktree
`../qumbra-lab-w3`, off `main` `bcb6b0a`. Multica QUM-181. The PR is never merged by this
session. Design source: `qumbra-design/l2-own-circuit-decision.md` §2–§3 (DECIDED 2026-09-22).

---

## Stage 0 — the task book's citations, checked

Every row read on `bcb6b0a`, not inherited.

| the book says | what I found |
|---|---|
| six locks: `consensus_cfg_is_value_locked`, `consensus_wire_is_148625_bytes` (`qlab-consensus/src/lib.rs`) | ✅ `:225`, `:285` |
| `q69_trace_width_is_read_off_the_matrix` (643), `q69_quotient_degree_does_not_move` (deg 4 / 4 chunks) (`qlab-air/src/narrow.rs`) | ✅ `:2825`, `:2877`; the width pin is 643 absolute + the 617+3+23 accounting; the degree test pins deg 4, 4 chunks, 937 constraints, 15 deg-4 |
| both `assert_eq!(BUCKET_PERMS, 84)` sites (`narrow.rs`) | ✅ `:2643`, `:3294` |
| `genesis_hash_is_pinned` + `t2_genesis_hash_is_pinned` (`qumbra-node/src/genesis.rs`) | ✅ `:1066`, `:1255` |
| `NarrowKeccakAir` layout: `ROLE_ARHO = 14` spent, role codes 4-bit, 96-slot ring, 13 witness lanes, `PV_LEN = 84` | ✅ `narrow.rs:184-237`, `:260-269` — **15 codes used, 4-bit codes hold 16: shape S needs 17** (finding 1 below) |
| `qlab-note::note_commitment` + its lock `commitment_matches_qlab_air_build_bucket` | ✅ `qlab-note/src/note.rs:33`, `:128` |
| the mint's worked pattern: `docs/prompts/mint-combo-builder-prompt.md` + `docs/mint-combo-build-notes.md` | ✅ read in full; the forgery-shape tamper tests (republish the matching `cm`) and the column-by-column accounting are the standards followed here |
| freeze gadget: "none exists in-tree today" | ✅ no indexed-Merkle or SMT type anywhere in `crates/*/src` (grep for `indexed`, `sparse merkle`, `SparseMerkle`, `IndexedMerkle`: only unrelated hits) |
| L2 code in tree | ✅ none — no `l2` symbol in `qlab-air`, `qlab-note`, `qlab-bench` |
| bench discipline: measurement = release binary under `/usr/bin/time -l` inside `scripts/rig run`, one config per process | ✅ `docs/mint-combo-build-notes.md` §Stage 5 (the 25 MB non-number); `scripts/rig` read in full (240 lines) |
| the b4 anchor is `b4/q43/g22` | ✅ `qlab-bench/src/m4treerec.rs:27` `AGG_CFG` — imported, not copied |
| pre-registered: shape S b4 ≈ 5 GB / ~470 KB from the M3 b4 point 2.6 GB / 236 KB at 2^18 | ✅ `docs/bucket-M3-run1.md`: b4/q40 236.4 KB fixed at 617 × 2^18; footprint 2.6 GB is the M3 record. Scaling check: 2^18 × 617 × 4 B × 4 (b4) = 2.59 GB — the M3 footprint IS the LDE'd trace, which is the scaling law used in §5 below |

### 🔴 Two findings against the book's premises, before any code

1. **17 roles do not fit 4-bit codes.** Shape S needs `ROLE_AREG` (the registry leaf opening,
   a full-state override) and `ROLE_BREG` (its root bind). `narrow.rs` has codes 0…14 spent and
   one free. Every alternative that stays at 4 bits (merge `BNF1`/`BNF2` into a toggle latch;
   bind the registry root on the *next* chain's `AREG` boundary; drop a role) either rewrites the
   #219 latch's soundness argument or needs a new program-driven marker to tell the two
   openings apart. **Position: the L2 AIR uses 5-bit role codes** (32 codes; S spends 17, P
   gets 15). Cost: +8 ring limbs (128 program slots — S is 120 perms and 96 would not hold it
   anyway), +4 decomposition bits, +1 role bit, and **+4 materialized low half-selectors** so
   `sel = lo · pair(r2,r3) · bit(r4)` stays at degree 4 — the ceiling the 13 L1 selectors
   already set. Without the four `lo` columns the selectors would be degree 5 (same 4 quotient
   chunks, but a different census line).
2. **The book's "~118 perms" is 120 with a bind perm.** `AREG + 16 × MERKLE` is 17; the root
   bind is one more (`BREG`, no injection, the bind bank captures its boundary `a[0..4]`), so
   the registry costs 18 per input: 84 + 36 = **120**. 2^19 holds 170; nothing moves.

## Stage 0 — what will be created, and the locks

| file | what |
|---|---|
| `crates/qlab-air/src/l2.rs` | **new** — `L2ShapeSAir`, the registry types, `build_bucket_l2*`, the trace fill, the tests (positives, the six negatives, q69-style accounting, degree) |
| `crates/qlab-air/src/lib.rs` | `pub mod l2;` (one line) |
| `crates/qlab-note/src/l2note.rs` | **new** — `L2Note`, `note_commitment_l2`, the byte-for-byte lock against `build_bucket_l2` |
| `crates/qlab-note/src/lib.rs` | `pub mod l2note;` (one line) |
| `crates/qlab-bench/src/l2shape.rs` | **new** — the `l2shape` mode: `--shape s|s20|mock118|mock240|p`, `--only <lane>` |
| `crates/qlab-bench/src/main.rs` | the mode registration (one arm) |
| `docs/w3-build-notes.md`, `docs/w3-run1.md`, `docs/w3-run2.md` | this file; the two run docs (paired `-zh` at stage 1) |

**The six locks are outside the diff by construction**: `git diff origin/main -- crates/qlab-air/src/narrow.rs crates/qlab-consensus crates/qumbra-node` is empty and stays empty. The L2 module is a *fork* of `narrow.rs`'s engine (the 371-column Keccak pipeline, the program machinery, the three banks, the latch, the marker — reproduced structure for structure), not a shared abstraction: extracting the column-offset chain / `SlotWitness` / `SEL_CODES` pattern is the lock-touching refactor #700 names as a stage boundary, and this baton did not take it. Pure `pub` helpers with identical semantics are imported from `narrow` (`MerkleWitness`, `derive_output_rho`, `pv_chunks`, the fabricated-tree helpers). The cost is ~2,100 lines of engine duplicated; the price of the alternative is a stage boundary on the frozen circuit. Recorded as a follow-up, not taken.

## Stage 0 — shape S as designed (built as a draft in the same commit; unmeasured, un-CI'd at the time of the stage-0 post)

### Program (120 perms, 2^19)

```text
[DUMMY]
per input k:  ANK → NF → BNF_k → AREG → 16×MERKLE → BREG → ARKM → ACM → 32×MERKLE → BANCHOR   (56)
ACMOUT_0 → BCM1 → ARHO → ACMOUT_1 → BCM2 → BAL → END                                          (7)
```

**Position: the registry opening sits inside the input chain, between `BNF_k` and `ARKM`.** Both
`AREG` and `ARKM` are full-state overrides, so the Keccak chain is severed on both sides of the
insertion and neither equality bank sees it (bank 1 accumulates at `NF`/`ARKM`, bank 2 at
`NF`/`ACM`; the 18 registry perms fire neither gate). What the placement buys: the #219 latch `L`
— program-driven, high across exactly chain 1's `BNF2`-close → `BANCHOR`-close span — now covers
chain 1's `AREG` too, so **`L` alone distinguishes the two inputs' `ACM`s AND the two registry
openings**, and `M` (the #215 marker) the two outputs. No new marker column, no new role for
"the second opening". The latch span test is re-pinned for the wider span.

### Roles and lanes

- 5-bit codes; `ROLE_AREG = 15`, `ROLE_BREG = 16`; 0…14 identical to `narrow.rs`.
- 15 witness lanes: the L1's 13 + `W13 = asset` + `W14 = flags`.
- `ACM`/`ACMOUT`: the 112-B note block — `value W4 | asset W13 | rkm (chain / W0..3) | ρ W5..8 | rseed W9..12 | pad @ bit 896`. `ARHO` unchanged (ρ′ derivation carries over; `ROLE_ARHO`'s `W5..8` lanes are still ACMOUT's ρ′ lanes).
- `AREG`: `asset W13 | issuer_key W0..3 | mode W4 | freeze_root W5..8 | allow_root W9..12 | flags W14 | pad @ bit 960` — lane-aligned (120 B; the design's 106 B is the byte-packed figure — same one block). **Shape S constrains `mode = Cloaked (0)` bit by bit on the absorb; `flags` is absorbed (bound into the root) and not read.**
- `PV_REGROOT` = 16 chunks after `PV_FEE`; `PV_LEN = 100`. `BREG` joins the bind roles and closes against it; the #219 `L·dv` relaxation stays on the ANCHOR close only — a dummy slot still opens asset 0's leaf.

### Two-asset balance — the construction, and a bug it had for forty minutes

**Position: asset ids are 16-bit registry indices.** The design's registry is depth 16 (§2.4) and
`asset` is "a registry index"; the u64 note lane is the wire encoding. The circuit forces bits
16…63 of every absorbed asset lane (`ACM`, `ACMOUT`, `AREG`) to zero via a new periodic
`lo16 = [z < 16]` column (free), so one field element per note carries the whole id: six
capture-and-hold accumulators (`A₁, A₂, O₁, O₂, R₁, R₂`, chunk 0 of `W13` under six
materialized gates off `L`/`M`) and every comparison is same-row at `BAL`'s close. The 64-bit
alternative is 4 chunks per id and 4 inverse witnesses per `≠` — ~50 columns more for a
domain the registry cannot address anyway.

Rows: row 1 is `A₁`'s, row 2 is `A₂`'s. Selectors (witness bools, constant like `dv`):
`o1a`, `o2a` (output `j` accounted in row 1 or row 2), `f1` (fee charged to row 1 or 2), and
`q` (`A₁ = A₂`). Bound at the close: `o_ja ⇒ O_j = A₁`, `¬o_ja ⇒ O_j = A₂`, `f1 ⇒ A₁ = 0`,
`¬f1 ⇒ A₂ = 0`, `q ⇒ A₁ = A₂`, `¬q ⇒ qinv·(A₁ − A₂) = 1`, `R_k = A_k`. Under `¬q` each row
closes on its own 16-bit-limb borrow chain (row 1 against `f1·fee`, row 2 against `(1−f1)·fee`);
under `q` the rows are **summed** and close once against the whole fee.

🔴 **The first draft had no `q` and no sum** — "assignment form: every output in exactly one row,
the fee in exactly one, so per-asset conservation follows and `A₁ = A₂` needs nothing special".
The soundness argument is right; the *completeness* argument is wrong: with `A₁ = A₂` an honest
`60 + 40 = 70 + 25 + 5` has **no per-row partition** (no subset of {70, 25, 5} sums to 60 or 40),
only a per-asset one. Caught writing the selector-corner test, before CI. The `q` selector costs
4 columns (`q`, `qinv`, and the two materialized `close·q` / `close·(1−q)` gates) and is bound
both ways, so a lying `q` is refused whatever else the prover does — `l2_shape_s_selector_corners_satisfy`
checks both lies. **Dummy inputs carry asset 0, value 0**: both forced by the AIR
(`INJ3E · L·dv · W4 = 0`, `INJ3E · L·dv · W13 = 0`).

### Column accounting over 643 → **702** (test-locked in `l2_trace_width_is_read_off_the_matrix`)

| # | group | columns |
|---|---|---|
| 17 | 5-bit roles | PR ring 24 → 32 limbs (+8), `D` 16 → 20 bits (+4), `RB` 4 → 5 (+1), `LO` half-selectors (+4) |
| 6 | shape-S roles | `sel(AREG)`, `sel(BREG)`, `inj(AREG)`, `SE[areg]`, `BGC[breg]`, `INJRE = inj(areg)·ep` |
| 2 | witness | `W13 = asset`, `W14 = flags` |
| 21 | assets | `AG` 6 gates, `AC` 6 accumulators, `SEL2` 4 (`o1a`, `o2a`, `f1`, `q`), `QINV` 1, `CQ` 2, `SG` 2 |
| 13 | balance row 2 | `BL2` 4, `BLC2` 9 |
| **59** | | 643 → **702** |

Max constraint degree **4** (the 16 role selectors + `EG3[1]`, exactly the L1's shape), 4
quotient chunks; test-locked in `l2_quotient_degree_matches_the_l1` with the deg-4 population
pinned at 17 (L1: 15). Everything new is ≤ 3 by materialization, the file's convention.

### Tests as written (CI is the only place they execute — CLAUDE.md, agent rule)

| test | pins |
|---|---|
| `l2_chain_only_satisfies_constraints`, `l2_chain_matches_reference_rounds` | the engine is the L1's |
| `l2_registry_chain_matches_reference` | `AREG → 16 × MERKLE` = reference leaf hash + fold, read off the trace, resolves to the fabricated root |
| `l2_acm_block_matches_reference` | the 112-B note block, `st[1] = asset`, against `reference::keccak_f` |
| `l2_shape_s_satisfies_constraints`, `l2_shape_s_selector_corners_satisfy` | the full S instance at 2^19; same-asset spend (the sum), fee on input 2, outputs swapped; both `q` lies refused |
| `l2_neg_output_asset_from_nowhere` | negative 1 — third asset on an output, `cm` republished, all 16 selector assignments refused |
| `l2_neg_cross_asset_balance` | negative 2 — totals balance, per-asset do not; the per-asset-balanced twin verifies |
| `l2_neg_fee_in_wrong_asset` | negative 3 |
| `l2_neg_no_fee_asset_note` | negative 4 — two stablecoin inputs, fee 0, still refused; with an asset-0 input it verifies |
| `l2_neg_registry_leaf_under_wrong_root` | negative 5 — (a) forged `PV_REGROOT`; (b) a genuine opening of *another asset's* leaf under the genuine root |
| `l2_neg_mode_not_cloaked` | negative 6 — a Hybrid leaf genuinely in the registry; its Cloaked twin (issuer_key + flags set) verifies |
| `l2_public_value_negatives`, `l2_output_rho_is_still_bound` | the L1 set carries over (nf1/fee/anchor/cm2; a free ρ′₀ with matching `cm`) |
| `l2_asset_id_is_a_16_bit_registry_index` | 2^16 refused on input, output; 0xffff verifies |
| `l2_trace_width_is_read_off_the_matrix`, `l2_quotient_degree_matches_the_l1` | the accounting above |
| `l2_program_geometry`, `l2_latch_span_covers_chain_1_including_its_registry_opening`, `l2_asset_captures_read_the_right_lanes` | layout, the widened latch span on all 2^19 rows, the six captures |
| `l2_dummy1_satisfies_constraints`, `l2_dummy1_stablecoin_spend`, `l2_dummy_slot_value_and_asset_must_be_zero`, `l2_dv_cannot_make_slot_0_a_dummy` | the #219 set on L2, plus asset 0 forced |
| `qlab-note::l2note::l2_commitment_matches_qlab_air_build_bucket_l2` | the L2 twin lock |
| `qlab-bench::l2shape::{l2shape_lanes_are_at_the_floor, l2shape_mock_program_is_the_padded_l1_shape, l2shape_shape_s_prove_verify_roundtrip_b4}` | the lanes clear the floor; the mock is the padded L1 shape and is SAT; S proves and verifies through the real prover at b4/q43 |

## Stage 0 — the geometry mock

`l2shape --shape mock118|mock240`: the shape-S AIR carrying the L1-shaped 84-perm program
(assets 0, no registry opening) padded with `ROLE_MERKLE` slots after `END` to 118 perms — the
padding injects pseudo-random siblings and chains onward, real Keccak work bound to nothing.
`mock118` @ 2^19; `mock240` = the same program @ 2^20 ("240" is the height: the 128-slot ring
cannot express 240 program perms, and the pipeline chains through padding regardless, so the
prover's work is the height's, 341 perms of it). **Labelled MOCK; gates nothing.**

**Projection [derived, the LDE law]:** footprint ≈ `rows × width × 4 B × blowup` (the M3 point
2^18 × 617 × 4 × 4 = 2.59 GB reproduces the recorded 2.6 GB):

| shape | lane | projected footprint |
|---|---|---|
| S / mock118 (702 × 2^19) | b4 | **5.9 GB** |
| S / mock118 | b8 | **11.8 GB** |
| mock240 / s20 (702 × 2^20) | b4 | **11.8 GB** |
| mock240 / s20 | b8 | **23.5 GB** |
| S | b16 | 23.5 GB (allowed by the canary rule only if b8 projects it < 32 GB: 2 × 11.8 = 23.5 ✓, but see the rig ask) |

The measured table lands in `docs/w3-run1.md` / `w3-run2.md` once the rig ask below is
answered.

## Stage 0 — the freeze-gadget census (stage 2's question, priced now)

Common to both: the freeze root is **not a public value** — it is `AREG`'s `W5..8`, so the
non-membership fold binds through an equality bank (`+a[0..4]` at the bind perm's boundary,
`−W5..8` at `AREG`'s; one accumulator, two windows disjoint in program order) rather than a PV
close. Both need the input's `rkm` as a *chained* digest at the gadget's first perm and again at
`ACM`, so both spend one re-derivation perm per input (`ARKM` again — a second code without
bank-1 legs, +1 selector, 0 other columns; cheaper than a 19-column rkm bank). The allowlist
path (a `cred = H(rkm ‖ D_CRED)` perm reading the chain, 20 `MERKLE`, a bind through the same
bank against `W9..12`) costs 22 perms/input either way, and `AISS` 1 perm per asset bound
**same-row** to `AREG`'s `issuer_key` lanes (place it immediately before `AREG`: its digest is
`AREG`'s boundary `a[0..4]`, and `W0..3` is the leaf's issuer_key — a bit-serial equality, 0
columns).

| | (a) indexed Merkle, depth 20 | (b) SMT-64 over `Keccak(rkm)[0..8]` |
|---|---|---|
| perms per policy input | `AFRZ` (low-leaf hash, reads chained rkm as `a`, absorbs `key_lo ‖ key_hi` as `W0..3 ‖ W5..8`) + 20 `MERKLE` + bind + `ARKM′` = **23** | `AKEY` (`H(rkm ‖ D_K)`, NF-shaped) + 64 `MERKLE` + bind + `ARKM′` = **67** |
| shape P perms (S 120 + freeze + allowlist 2×22 + `AISS` 2 + `ARKM″` 2) | **≈ 214** | **≈ 302** |
| height | 2^20 (341 capacity, 63 % used) | 2^20 (341 capacity, **89 % used — 39 spare perms from the 2^21 cliff**) |
| program ring | 56 limbs (224 slots): +24 columns over S | 80 limbs (320 slots): **+48 columns over S** |
| gadget-specific columns | the two 256-bit comparisons `key_lo < rkm < key_hi`, **bit-serial on `AFRZ`'s boundary rows** where `rkm` (chained `a`), `key_lo` (`W0..3`) and `key_hi` (`W5..8`) share rows: per comparison 4 running `lt` + 4 running `eq` flags (one per lane, LSB→MSB over z) and a materialized lane-combine ≈ 12; two comparisons ≈ **24** | the 64 path bits must equal `k`'s bits: `k` is the `AKEY` digest's lane 0, each `MERKLE` step's `pbit` is a per-perm constant, so the binding needs a per-perm weight (a power-of-two register reset every 16 steps + a 4-bit step counter, or a 16-slot one-hot ring) and 4 chunk accumulators ≈ **25** |
| bank for the root | 16 acc + 4 gates + 2 SE ≈ 22 (shared with the allowlist window) | same |
| roles | `AFRZ`, `BFRZ`, `ACRED`, `BALLOW`, `ARKM′`, `AISS`: 6 sel + 3 inj + ~3 SE ≈ 12 | `AKEY` instead of `AFRZ`: same count |
| `vPublic` + mint gating | ≈ 8 (2 sign bits, 2 mint selectors, row-chain terms; +10 PVs) | same |
| **projected width** | 702 + 24 + 24 + 22 + 12 + 8 ≈ **790** | 702 + 48 + 25 + 22 + 12 + 8 ≈ **815** |
| constraint degree | 4 (comparison flags materialize to ≤ 3) | 4 |
| projected P b4 footprint [LDE law] | 2^20 × 790 × 16 B ≈ **13.3 GB** | ≈ **13.7 GB** |
| semantics | exact non-membership | 2⁻⁶⁴-per-pair collision, DoS-only |
| reuse | **W2′ needs it for `cnf`** (l2-architecture §5 (2)) | none |

**Recommendation: (a), the indexed Merkle tree.** The task book expected the gadget to decide
"where in the 200–240 range" P lands; the census says **both land at 2^20** — S + allowlist +
registry already exceed 2^19's 170 perms, so the freeze gadget's 44-perm difference buys no
height, and at a fixed height a perm costs nothing (#219's six-arm measurement, reconfirmed by
the mint: the added permutation cost zero bytes). What separates them is width (≈ 25 columns in
(a)'s favour, mostly the ring), the 2^21 cliff (b) sits 39 perms from, exactness, and W2′'s
reuse. (a)'s comparisons are the one piece with no in-tree precedent; they are cheap *because*
`AFRZ` reads `rkm` off the chain on the same rows it absorbs the two keys, which is the same
"put the two values on one perm's boundary rows" move option 4 used for ρ′₁. **Self-ruled
pending** if the coordinator does not answer within 12 h (#700's fallback rule); stage 2 is
baton 2 either way.

🔴 **Envelope note, derived not measured**: both (a) and (b) project shape P at b4 to
**13–14 GB against the 16 GB gate** — inside, with ~15 % margin, not the ~10 GB the book
pre-registered. The pre-registration scaled from 2.6 GB by height alone (×4); the width also
grows (617 → ~790, ×1.28). If the mock240 measurement lands at the LDE law, that margin is what
stage 2 inherits, and the "< 2× out → one tuning round" lever is the tree depths (freeze 20 →
16 saves 8 perms — nothing at fixed height) or **b2** (halves the LDE; bytes ×~1.7).

## Stage 0 — the b8 query count, derived

Under the 2197-corrected accounting (`fri-soundness-accounting-2026-07.md` §6) the conjectured
figure is `q · β(ρ) + g`, `β(ρ) = −log₂(1 − δ*(ρ))` bits per query at the base-field
list-decoding radius. The three ruled lanes fix β: `(96.9 − 22)/20 = 3.745` (b16),
`(96.1 − 22)/40 = 1.853` (b4), `(94.8 − 22)/80 = 0.910` (b2) — and B″'s q21/q43/q86 reproduce
100.6 / 101.6 / 100.2 from exactly those rates. `1 − δ* = 2^−β` puts δ* at 0.925 / 0.723 / 0.468,
i.e. 0.012 / 0.027 / 0.032 below capacity `1 − ρ`. For b8 (capacity 0.875) the gap brackets
between b4's and b16's: δ* ∈ [0.848, 0.863], **β ∈ [2.72, 2.87] bits/query**. At g22 the ≥ 100
floor needs q ≥ 78/β ∈ [27.2, 28.7]; **q29** clears the conservative end (29 × 2.72 + 22 =
100.9) and is the lane: `b8/q29/g22/fp16/a16`. The exact Cor. 4.5 optimisation at ρ = 1/8 was
not run; if it lands above 2.72 the lane is ≥ 1 query conservative, never short. (The old
capacity proxy `make_config_with` asserts reads 29 × 3 + 22 = 109.) Test-locked in
`l2shape_lanes_are_at_the_floor`.

## Stage 0 — 🔴 the rig ask (posted on #700 with the stage-0 report)

CLAUDE.md (2026-08-19, Larry's order): agent sessions run **no `cargo test`** locally, only
`cargo check` / `cargo clippy`; the acceptance bar is the `verify-graviton` lane. The workspace
brief adds: no benchmarks or heavy builds unless an issue explicitly asks **and then only after
asking on the issue first**. #700 explicitly asks for release-binary measurements under
`scripts/rig run`. So, asked on #700 before any of it runs:

1. a release build of `qlab-bench` in this worktree's own `target/` (cold; the plonky3 stack —
   minutes of full-core load);
2. the light lanes: S and mock118 at b4 (≈ 5.9 GB projected) and b8 (≈ 11.8 GB), mock240 / s20
   at b4 (≈ 11.8 GB) — each one process under `/usr/bin/time -l` inside `scripts/rig run`;
3. the heavy lanes: mock240 / s20 at b8 (≈ 23.5 GB) and S at b16 (≈ 23.5 GB) — on a 36 GiB
   machine currently carrying ~21 GB of other residents, these would compress or swap, and a
   swapped run is disqualified by the book's own rule.

Until answered: the code is pushed, the PR is open, the CI lane runs the tests. **No
measurement has been taken; every number above is a projection and is labelled so.**

## Stage 0 — RULED (lab #700, 2026-09-22 ~17:55 +08)

Gadget **(a) indexed Merkle — ruled** (not self-ruled). Every position above accepted; the envelope
re-registered at 13–14 GB projected against the unchanged 16 GB / 20 s gate; rig ask answered:
build YES, light lanes YES, heavy lanes (2^20 b8, S b16) NOT this baton; the CI runner is offline,
so ONE scoped local test run of the three touched crates was permitted (never `--workspace`);
workspace-suite acceptance is owed, not waived. Two stage-1 additions: the note twin must
**refuse** an id ≥ 2^16; the `q` lie both ways and the option-4 forgery shape under the dummy
latch as named negatives.

---

## Stage 1 — MEASURED (2026-09-22 18:43–18:47 +08; `docs/w3-run1.md` / `docs/w3-run2.md` + `-zh`)

### The ruling's additions, as built (`e236f7f`)

| test | pins |
|---|---|
| `qlab-note::l2note::l2_plaintext_refuses_an_asset_id_outside_the_registry_space` | `from_plaintext` returns `None` on `asset ≥ 2^16` (0xffff parses; 2^16 and `u64::MAX` refused, never truncated) |
| `l2_neg_q_lie_is_unsat_both_ways` | `q = 0` on equal assets and `q = 1` on distinct assets, each against all eight other assignments, on witnesses honest in every other respect |
| `l2_dummy_shape_forged_seed_is_refused` | under `dv = 1`: both seeds derive from the REAL slot 0's nullifier, the dummy's invented one feeds no seed, and a forged ρ′₀ / ρ′₁ with its commitment republished is refused under every assignment |

### The scoped test run — 216 passed / 1 failed / 0 ignored, then the one fixed

`scripts/rig run -- cargo test --release -p qlab-air -p qlab-note -p qlab-bench --no-fail-fast -- --test-threads=1`
(`--no-fail-fast` per CLAUDE.md's enumerate-and-accept-in-one-run rule), wall 2,604 s, sampled
peak test-binary RSS 16.7 GB (the bench crate's pre-existing prove-carrying tests, not the L2
ones — declared in the run doc). `qlab-air` **64/0** (26 `l2::`), `qlab-note` **39/0** (4
`l2note::`), `qlab-bench` 113/1: `l2shape_mock_program_is_the_padded_l1_shape` asserted 118
non-dummy roles where the 118-perm program has 117 (warm-up convention). Fixed in `8a20234`;
re-run alone under the lock: 1/1 in 6.2 s.

**The one deliberate change after the run**: `any_assignment_satisfies` now iterates the 8
`(o1a, o2a, f1)` assignments at the witness's `q` instead of 16 with `q` free — `q`'s two
constraints read only the captured `A₁`/`A₂`, so its lie is refused independently
(`l2_neg_q_lie_is_unsat_both_ways` is that proof), and the 16-way form cost ~27 of the 43
minutes. The 8-way assertions are a strict subset of the ones the run executed; **the 8-way
code has not itself been executed** — declared here and in the run doc.

### What the measurement says (max of samples; every row zero swap; full tables in the run docs)

| row | footprint | prove (clean sample) | fixed bytes |
|---|---|---|---|
| **shape S b4** | **6.80 GB** | **1.52 s** | **285,605 B** |
| **shape S b8** | **13.76 GB** | **2.58 s** | **206,221 B** |
| shape S @ 2^20 b4 (P-height proxy) | **14.11 GB** | 3.19 s | 297,989 B |
| mock118 / mock240 | within 2 % of S at equal geometry | | |

- 🔴 **The LDE law under-projects by ~15 % at this geometry** (6.78 vs 5.9; 13.76 vs 11.8; 14.11
  vs 11.8), invisibly at the M3 point (2.59 vs 2.6). The stage-0 P projection inherits it:
  **shape P at b4 re-projects to 15.6–15.9 GB** (= 2^20-b4 measured 13.9–14.1 × 790/702) against
  the 16 GB gate — **1–3 % margin, not 15 %**. Prove ≈ 3.6 s against 20 s is not a concern. This
  is the stage-1 headline for the coordinator; the lever named at stage 0 (b2) stands.
- **Bytes came in −39 % under the book** (285.6 KB vs ~470 KB): proof size follows log_height
  and width, not rows.
- **b4 is the lane** on the design's own criterion (§2.5, RAM not bytes): b8 buys −28 % bytes for
  2.0× RAM and +70 % prove.
- Reproduction: bytes byte-identical; footprints to the megabyte on 4 of 6 rows; S b8 and s20 b4
  take discrete values (13.48/13.76; 13.56/13.89/14.11) — a third and fourth sample each found a
  pair inside ±1 %, and **max RSS was the reproducible metric at this size** (4/4 at 14.11 on
  s20), the reverse of the 30 GB-class finding. Two contaminated-time samples (`sys` 2–3×,
  instructions flat) discarded for prove time, kept for footprint.

### Drafted measured-update block for `l2-own-circuit-decision.md` §2.3 (the coordinator carries it)

> **Measured update (2026-09-22, [qumbra-lab PR #701](https://github.com/qumbra-labs/qumbra-lab/pull/701) — W3 stage 1, shape S real, reproduced twice + 3rd/4th samples, zero swap): shape S is built and measured; shape P is projected from its 2^20 twin.** Shape S as built: **702 columns** (643 + 59, accounted column by column and test-locked), **120 perms → 2^19** (registry opening = `AREG` + 16 `MERKLE` + a bind perm, 18/input), max constraint degree 4 / 4 quotient chunks (the L1's ceiling — 5-bit role codes with four materialized half-selectors), 100 public values (+ `registry_root`), asset ids = 16-bit registry indices (shape v1's id space = the registry depth), two-asset balance in assignment form with a both-ways-bound `q = [A₁ = A₂]`. **Measured (Apple M5 Max / 36 GiB, lab rev 8a20234, release binary under `/usr/bin/time -l` in `scripts/rig`, one lane per process, best-of-3 prove): b4/q43/g22 = 6.80 GB peak footprint / 1.52 s / 285,605 B fixed; b8/q29/g22 = 13.76 GB / 2.58 s / 206,221 B; the same AIR at 2^20 b4 = 14.11 GB / 3.19 s / 297,989 B.** Three corrections to this section's estimates: (1) the "~118 perms" is 120 (bind perm); (2) bytes are ~40 % under the pre-registration (proof size follows log_height and width, not rows); (3) RAM is ~15 % *over* the LDE-law projection at this geometry — and therefore **shape P at b4 projects to 15.6–15.9 GB against the 16 GB gate** (2^20-b4 measured × 790/702 columns, gadget (a) indexed Merkle as ruled), a 1–3 % margin; prove ≈ 3.6 s against 20 s. **The L2 lane is b4** (§2.5's criterion, now with both numbers: b8 = 2.0× RAM for −28 % bytes). b8's query count is q29/g22 (β ∈ [2.72, 2.87] bits/query bracketed from the three ruled lanes' 2197-corrected rates). Shape P's freeze gadget: **(a) indexed Merkle, depth 20 — ruled**; both gadgets land at 2^20 (S + allowlist + registry already exceed 2^19), so the gadget decides width, not height. b16 and 2^20-b8 not measured (heavy lanes deferred). Runs: lab `docs/w3-run{1,2}.md`.

### Stage 1 — status

| item | state |
|---|---|
| AIR, note twin + lock, `build_bucket_l2`, the six negatives + the ruling's three, q69-style accounting, `l2shape` mode | ✅ built; `qlab-air` 64/0, `qlab-note` 39/0, `qlab-bench` 114/0 after the one arithmetic fix (scoped run + single re-run, both under the lock) |
| measured at b4/b8, reproduced twice, `docs/w3-run{1,2}.md` + `-zh` | ✅ (light lanes; heavy lanes deferred by ruling) |
| measured-update block for §2.3 | ✅ drafted above |
| workspace suite | **NOT RUN — runner offline** (owed) |
| stage 2 (shape P) | baton 2 |

---

# Baton 2 (stage 2 — shape P; Multica QUM-182)

Fresh session, the branch is the memory. Read in order: CLAUDE.md, #700 + the two rulings, the
stage-0/1 posts, this file, `l2-own-circuit-decision.md` §2–§3. Same worktree
(`../qumbra-lab-w3`, recreated from the branch), same PR #701, never merged by this session.

## Stage 2 — the ruling's rows, checked on `49a632a`

| the ruling says | what I found |
|---|---|
| carry-over (i): the 8-way `any_assignment_satisfies` unexecuted | ✅ `l2.rs:2428`, iterates `0..8` at the witness's `q` — executed first (below) |
| carry-over (ii): no prover-stack tampered-PV test on L2 | ✅ `l2shape.rs` had `l2shape_shape_s_prove_verify_roundtrip_b4` only (honest surface) |
| gadget (a) ruled: low-leaf opening, `key_lo < rkm < key_hi` bit-serial on `AFRZ`'s boundary rows, one depth-20 path, `ARKM′` | ✅ built as ruled, with one placement change the census did not have (the root binding, below) |
| `AISS` same-row-bound to `AREG`'s issuer_key lanes | ❌ **not buildable as the census wrote it** — `AREG`'s boundary rows carry one chained digest, and the freeze fold's root is the better tenant (it saves a 16-column accumulator; `AISS` costs nothing on the bind bank's idle span). Position taken, reported |
| "mode read as flags (Hybrid/Regulated/Cloaked-with-vPublic=0)" | ✅ built; §3.6's parenthetical "Cloaked (or issuer with mint only)" is NOT built — the ruling's phrase is the stricter one and was taken (a finding for the design doc, below) |
| width ~790 decides the gate; > ~810 say so first | ✅ **774 by construction, read off the matrix** (`l2p_trace_width_is_read_off_the_matrix`) |
| both lanes: `b4/q43/g22` and `b2/q86/g22` | ✅ `l2shape` gains `B2_CFG` (the `m4interior` point, imported by value) and `--shape p`, `--shape p19` (the canary) |

## Stage 2 — the carry-overs (executed first, under the lock)

- (i) `cargo test --release -p qlab-air -- --test-threads=1 l2_neg_output_asset_from_nowhere l2_neg_cross_asset_balance`: **2 passed / 0 failed, 110.15 s** — 18 `check_all_constraints` at 2^19 (each negative: one honest precondition + eight assignments). The 8-way helper is now executed code.
- (ii) `l2shape_shape_s_tampered_pv_is_rejected_b4` (`l2shape.rs`): ONE 2^19 b4/q43 prove of the honest shape-S instance through `p3_uni_stark::prove`, then `anchor`, `nf₁`, `fee`, `registry_root` flipped in turn in the public values handed to `verify`, each must `Err`. **1 passed, 1.85 s** (the L1's `rejects_a_tampered_public_surface`, on L2). Commit `9aaa1cd`.

## Stage 2 — shape P as built (`crates/qlab-air/src/l2p.rs`, a second fork of the engine)

`l2.rs` is measured and test-locked at 702 / deg 4 / population 17, so P is **a new AIR type beside S**
(`L2ShapePAir`), not an edit — the same discipline S applied to `narrow.rs`. Pure helpers are imported
from `l2` (registry types, note block, `derive_input_l2`, the fabricated trees) and `narrow`.

### Program (212 perms → 2^20; per input 102)

```text
[DUMMY]
ANK NF BNF_k AISS ARKM AFRZ 20×MERKLE AREG 16×MERKLE BREG ARKM′ ACRED 20×MERKLE BALLOW ARKM″ ACM 32×MERKLE BANCHOR   (×2)
ACMOUT_0 BCM1 ARHO ACMOUT_1 BCM2 BAL END
```

The registry opening moved from "between `BNF` and `ARKM`" (S) to **after the freeze fold**, because the
freeze root is then the chained digest on `AREG`'s boundary rows — where the leaf's `freeze_root`
lanes `W5..8` already are. The latch `L` still spans chain 1's `BNF2`-close → `BANCHOR`-close, so it still
tells the two `AREG`s, the two `ACM`s and now the two policy chains apart. No new marker.

### The binding problem the census under-priced, and the answer taken

The Keccak chain carries one digest. `rkm` must be **chained** at three boundaries — `AFRZ` (the
comparison reads it as `a[0..4]`), `ACRED` (`H(rkm ‖ D_CRED)` absorbs it) and `ACM` (the note block) — so
it is derived three times (`ARKM`, then two `ROLE_ARKM2` with no bank-1 legs). The census's "+1
selector, 0 other columns" is right about the perm and wrong about soundness: an unbound `ARKM′` lets
the prover freeze-check any `rkm′` it likes. The three outputs must be tied together, cross-row, twice —
and every cross-row tie in this engine is an equality-bank window (16 accumulator columns each if new).

**Zero new accumulators.** Every window shape P needs rides a bank that is idle over exactly that span:

| window | + leg | − leg | close | bank |
|---|---|---|---|---|
| `rkm@AFRZ = rkm′@ACRED` | `INJ_AFRZE` (a) | `INJ_ACREDE` (a) | `CLOSE_CRED`, reset | **third bank** `EQ3` — idle until the outputs |
| `rkm′@ACRED = rkm″@ACM` | `INJ_ACREDE` (a) | `INJ3E` (a) | `EG[5]` (ACM's end) | **bind bank** `BQ` — idle between `BREG` and `BANCHOR` |
| `AISS` digest = leaf.issuer_key | `EG[1]` (a at `ARKM`'s boundary) | `INJRE` (`W0..3`) | `CRQ = AREGE·RQ`, reset `AREGE` | **bind bank** — idle between `BNF` and `BREG` |
| allow fold = leaf.allow_root | `EGB·ALW` (a at `BALLOW`) | `INJRE·ALW` (`W9..12`) | `EGBC` | **bank 1** — idle after `ARKM` closes |
| freeze fold = leaf.freeze_root | — | — | same-row at `AREG`: `AG_Rk·(hy_k+rg_k)·(a[l] − W[5+l]) = 0` | none |

The windows are sequential on each bank (`BQ`: `BNF` · AISS · `BREG` · rkm′ · `BANCHOR`), and every leg is
`ep`-gated so the ring's wrap at 2^20 (212-slot period, 341 perms) fires nothing.

### The comparison (gadget (a)'s one piece with no in-tree precedent)

Two 256-bit comparisons, `key_lo < rkm` and `rkm < key_hi`, LSB → MSB over the 64 boundary rows: per
lane a running `LT` (`(1−x)y + [x=y]·LT`) and `EQ` (`[x=y]·EQ`) flag, seeded same-row at `z = 0` by
`sel(0)`, advanced by an `mrow`-gated transition (the first draft gated on `mrow·(1−u63)` and read
**degree 5** — periodic columns count one each in Plonky3's symbolic accounting; gating on `mrow` alone
lands the z=63 step on the T row's first slot, which is free and holds it), three materialized lane
combines `C1..C3`, and the verdict `INJ_AFRZE·u63·(C3 − 1) = 0`. 22 columns. Keys are four little-endian
lanes (lane 3 most significant); the tail leaf's `key_hi` is `MAX = 2^256 − 1` and the head's `key_lo`
is 0, so strict `<` excludes only `rkm ∈ {0, MAX}` (hash outputs; negligible). The low leaf is
`H(key_lo ‖ key_hi)` with a **leaf marker at lane 8 bit 3**, distinct from the Merkle node's pad at bit 0
— a leaf never collides with an interior node.

### `vPublic`, `AISS`, mode as flags

- Public values +12 (`PV_LEN` 100 → 112): per balance row `s` (1 = redeem), four 16-bit chunks `m`, and
  `vpa` — the asset id, bound to the row's captured asset when `m ≠ 0` (`close·Σm·(vpa − A_k) = 0`) and
  0 by convention otherwise (issuance is public by design; a transfer reveals nothing). Chunk ranges are
  the PV builder's job, as for `PV_FEE`.
- Each row's borrow chain closes on `in − out − [fee] + (1 − 2s)·m = 0`; carry offset moved from −2 to
  **−3** (range analysis: with the signed term the chunk carries span `[−3, 3]`). Under `q` the summed chain
  carries `vPublic₁` and `vPublic₂` must be 0 (`close_q·Σm₂ = 0`, `close_q·s₂ = 0`).
- Per input, constant witness bools bound in-circuit: `hy`/`rg` (to the `mode` lane's bits 0/1 at
  `AREG`, every other bit 0, `hy·rg = 0`), `ropen` (to `flags` bit 0), `nz` (to `Σm ≠ 0` via the
  nonzero-inverse `vpinv`); `REQ_k = nz_k·(1 − s_k·ropen_k)` materialized; `RQ`/`ALW` the current-input
  muxes off `L`. Gates: freeze check ⇔ `hy ∨ rg`; allowlist ⇔ `rg`; `AISS` checked ⇔ `REQ`; and
  **`Σm·(1 − hy − rg) = 0` — a Cloaked asset carries no `vPublic`.**
- `AISS = H(isk ‖ D_I)`, `D_I` = lane 4 bit 7; `ACRED = H(rkm ‖ D_CRED)`, `D_CRED` = lane 4 bit 15 (W3's
  placeholder, an L2 parameter).

### Column accounting over 702 → **774** (test-locked in `l2p_trace_width_is_read_off_the_matrix`)

| # | group | columns |
|---|---|---|
| 21 | program ring | 32 → 53 limbs (212 slots — exactly the program; a spare slot buys nothing at a fixed shape) |
| 8 | roles | `sel` ×5 (`AISS`, `AFRZ`, `ACRED`, `BALLOW`, `ARKM2`), `inj` ×3 (`AISS`, `AFRZ`, `ACRED`; `ARKM2` shares `ARKM`'s) |
| 7 | gates | `INJ_AFRZE`, `INJ_ACREDE`, `CLOSE_CRED`, `EGB`, `EGBC`, `AREGE`, `CRQ` |
| 22 | comparisons | 2 × (`LT` ×4 + `EQ` ×4 + `C1..C3`) |
| 14 | policy | `hy`, `rg`, `ropen`, `nz`, `vpinv`, `REQ` per input; `RQ`, `ALW` |
| **72** | | 702 → **774** — 16 under the census's ~790 (no new accumulator), 36 under the ~810 line |

Max constraint degree **4**, 4 quotient chunks (`l2p_quotient_degree_matches_the_l1`). The deg-4
population is **57**, pinned: 21 selectors + `EG3[1]` (S's pattern) + 16 comparison transitions + 16
bank-1 transitions (the `ALW`-gated legs) + `CLOSE_CRED`/`EGB`/`EGBC`. S's "everything new ≤ 3 by
materialization" convention was **not** followed for those 35: materializing them costs 4–5 columns for
no quotient benefit (4 chunks either way). Recorded as a position.

### Findings for the design doc (the coordinator carries them)

1. **§3.6's "Cloaked (or issuer with mint only)" is not what the ruling's "Cloaked-with-vPublic=0" says**,
   and the ruling was built: a Cloaked leaf's rows carry `vPublic = 0`, full stop. An asset that mints
   but has no policy is a Hybrid leaf without `redeem_open` in this v1. If the parenthetical is wanted,
   it is one flag bit (`mint_only`) and one gate change, not a width change.
2. **The census's "AISS same-row at AREG (0 columns)" and "bank for the root … shared with the allowlist
   window" both assumed a boundary or a bank that turned out to be needed twice**; the layout above is
   what actually closes, and it is 16 columns *narrower* than the census projected because the rkm
   re-derivation the census listed at "0 other columns" is where the real binding cost was — and it
   fits on idle banks.
3. **Registry well-formedness is a registry-transaction invariant, not a shape-P check**: S accepts a
   leaf with `mode = Cloaked` whatever its `freeze_root` says, so the third circuit must refuse a
   Cloaked leaf with policy roots. Not W3 cargo; named so nobody assumes P covers it.

## Stage 2 — MEASURED (2026-09-22 23:38–23:42 +08; `docs/w3-run3.md` / `w3-run4.md` + `-zh`)

Rev `20723c9`, release binary directly under `/usr/bin/time -l` inside `scripts/rig run`, one shape × one
lane per process, canary first, every row zero swap.

| row | peak footprint | max RSS | prove (best of 3) | fixed B |
|---|---|---|---|---|
| CANARY: P AIR chain-only @ 2^19, b4 | 7.56 / 7.39 GB | 7.675 / 7.679 | 1.69 / 1.74 s | 300,293 |
| **shape P @ 2^20, b4/q43/g22** | **15.06 / 15.11 GB** | **15.324 / 15.323** | **3.56 / 3.76 s** | **312,677** |
| shape P, b2/q86/g22 | **NOT MEASURABLE** — see below | | | |

- 🟢 **Shape P is inside the gate at b4: 15.11 GB peak footprint (max of two, 0.3 % apart), 15.32 GB max
  RSS, against ≤ 16 GB — 5.6 % / 4.2 % margin; 3.6–3.8 s against ≤ 20 s.** Not a tuning round, not a
  STOP. Stage 1's re-projection (15.6–15.9 GB) was 0.5–0.8 GB high because the width landed at 774, not
  ~790; the LDE-law under-projection (~15–16 %) is unchanged at this width.
- 🔴 **The b2 lane does not exist for a degree-4 AIR in p3-uni-stark 0.6.1.** With 4 quotient chunks the
  quotient domain (4N) exceeds a blowup-2 LDE (2N): the PCS re-extends the trace through its iDFT
  fallback (the canary's 10.5 GB at 2^19 b2 vs 7.6 at b4), the prover finishes, and **`verify` rejects
  with `OodEvaluationMismatch`** — for P and (control run) for **S**. The interior lane's b2/q86 works
  because that AIR has 2 chunks. Pinned by `l2shape_b2_is_not_a_lane_for_a_degree_4_air`. The stage-1
  ruling's "measure at both b4 and b2; b2 is a live option" cannot be executed as written; **the second
  lane needs a degree-3 variant** (~21 materialization columns → ~795; b2 then projects to ≈ 7.7 GB
  [derived]). That is a change to the degree the ruling froze, so it is priced and **not built** —
  coordinator's call.
- **b4 is shape P's L2 lane** by default and by measurement. The thinnest margin W3 has produced, and a
  real one (reproduced twice, swap-free). What it is *not*: a margin against a different machine's
  allocator or a bigger registry/freeze/allow depth — every depth is an L2 parameter (§6) and each extra
  level is one perm at fixed height (free) plus nothing in width; the height cliff is 341 perms (129
  spare).
- The P prover-stack tampered-PV test (`l2shape_shape_p_prove_verify_and_tampered_pv_b4`, one 2^20 b4
  prove, 6 flipped surfaces incl. `vpa₂`/`m₂`) and the b2 pin: **2/2, 5.9 s**, sampled test-binary RSS
  13.8 GB (1 Hz — under-samples a 20 s peak; the bench's 15.3 GB is the number).

### Drafted measured-update block for `l2-own-circuit-decision.md` §2.3 (the coordinator carries it)

> **Measured update (2026-09-22, [qumbra-lab PR #701](https://github.com/qumbra-labs/qumbra-lab/pull/701) — W3 stage 2, shape P built and measured, reproduced twice, zero swap; tracker [lab #700](https://github.com/qumbra-labs/qumbra-lab/issues/700)): shape P is real and inside the gate at b4; b2 is not a lane for this family.** Shape P as built: **774 columns** (702 + 72, accounted column by column and test-locked — 16 under the census's ~790 because no new equality bank was needed: every cross-row binding rides an existing bank's idle span), **212 perms → 2^20** (per input: `AISS`, `ARKM`, `AFRZ` + 20 `MERKLE`, `AREG` + 16 `MERKLE` + `BREG`, `ARKM′`, `ACRED` + 20 `MERKLE`, `BALLOW`, `ARKM″`, `ACM` + 32 `MERKLE` + `BANCHOR` = 102), max constraint degree 4 / 4 quotient chunks, 112 public values (+ `vPublic` per row: sign, four 16-bit chunks, and the revealed asset id). Gadget (a) as ruled: the indexed-Merkle low leaf `H(key_lo ‖ key_hi)` (leaf-marked, distinct from interior nodes), `key_lo < rkm < key_hi` bit-serial on `AFRZ`'s boundary rows (22 columns), one depth-20 path, **the fold's root same-row-equal to the leaf's `freeze_root` lanes at `AREG`** (zero columns — the registry opening sits after the freeze gadget for exactly this). `rkm` is chained at three boundaries and derived three times; the three derivations are tied by two windows on the third bank and the bind bank (the census's "0 other columns" re-derivation was unsound as written; this is where the binding cost was). `AISS` rides the bind bank's idle span, checked only when `REQ = nz·(1 − s·redeem_open)`. Mode read as flags: `hy`/`rg`/`redeem_open` bound bit-wise to the leaf; freeze ⇔ `hy ∨ rg`, allowlist ⇔ `rg`, **Cloaked ⇒ `vPublic = 0`** (§3.6's "issuer with mint only" parenthetical is not in v1 — one flag bit if wanted). **Measured (Apple M5 Max / 36 GiB, lab rev `20723c9`, release binary under `/usr/bin/time -l` in `scripts/rig run`, one lane per process, best of 3): b4/q43/g22 = 15.06 / 15.11 GB peak footprint, 15.32 GB max RSS, 3.56 / 3.76 s, 312,677 B fixed — inside the ≤ 16 GB / ≤ 20 s gate by 5.6 % (footprint) / 4.2 % (RSS) on RAM and 5× on time.** Two corrections to §2.3/§2.5 as amended at stage 1: (1) **the b2 lane is structurally unavailable to a degree-4 AIR in Plonky3 0.6.1** (4 quotient chunks need blowup ≥ 4; the prover re-extends and the verifier rejects with `OodEvaluationMismatch` — shape S too; the interior lane's b2 works at 2 chunks) — so "shape P is measured at both b4 and b2, its lane chosen by the larger margin" collapses to **b4, the only lane**, and a b2 option costs a degree-3 variant (~21 columns → ~795, ≈ 7.7 GB projected, not built); (2) the stage-1 P projection of 15.6–15.9 GB was 0.5–0.8 GB high (width 774, not ~790). The proof is 312,677 B (+4.9 % over S at the same height for +10 % width). The named fallback (one policy input per transaction → 2^19) is **not needed**. Registry well-formedness (a Cloaked leaf must carry no policy roots) is the registry transaction's invariant, not shape P's — named so it is not assumed covered. Runs: lab `docs/w3-run{3,4}.md`; workspace suite **not run — runner offline** (owed).

### Stage 2 — status

| item | state |
|---|---|
| carry-overs (i), (ii) | ✅ executed / built and run (`9aaa1cd`) |
| shape P AIR, builders, policy trees, `l2shape --shape p|p19`, b2 lane | ✅ (`398210b`, `20723c9`, `a01d2bf`) |
| the ruling's negatives + the S negatives on P | ✅ 31/31 `l2p::` (development run 1,489 s + 232 s; the scoped run below) |
| measured at b4, reproduced twice, run docs + `-zh` | ✅ |
| measured at b2 | ❌ **NOT MEASURABLE at degree 4** — finding, priced; a ruling is owed |
| §2.3/§3 measured-update block | ✅ drafted above |
| scoped test run (`-p qlab-air -p qlab-note` full, `-p qlab-bench l2` filtered) | ✅ **140 distinct tests / 0 failed** (141 result lines; the b2 pin ran twice) — `qlab-air` 95/0 (2,539 s), `qlab-note` 39/0, `qlab-bench` `l2` 5/0 + the skipped P b4 prover test 2/0 on its own; peak sampled 8.0 / 13.8 GB (`docs/w3-run4.md`) |
| workspace suite | **NOT RUN — runner offline** (owed) |
