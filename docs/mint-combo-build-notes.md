# mint-combo — builder working notes

Per-baton build notes for `docs/prompts/mint-combo-builder-prompt.md`. **Not paired** (CLAUDE.md:
build notes are written by a session for a session). Branch `claude/mint-combo` off `main`
`c23ac20`. The PR is never merged by this session.

---

## Stage 0 — the task book's citations, checked

PR #242's shape: every row read, not inherited. Tree is `c23ac20`.

| the book says | what I found |
|---|---|
| `CONSENSUS_WIRE_BYTES` at `qumbra-node/src/genesis.rs:72`, FROZEN v1.0, `145_609` | ✅ exact line, exact value |
| consumed at `genesis.rs:202` | ✅ `consensus_wire_bytes: CONSENSUS_WIRE_BYTES` in the `FrozenParams` literal |
| wire pin test `qlab-consensus/src/lib.rs:282` area | ✅ the feature-aware pin is `:275-290`; unfeatured asserts 145,609, featured asserts 145,957 |
| latch behind `q69-latch` in `narrow.rs`, decl at `qlab-air/Cargo.toml:15`, forwarded by `qlab-consensus/Cargo.toml:18` | ✅ all three; `narrow.rs:145-162` (columns), `:998-1013` (the transition), `:752-766` (the gated anchor close) |
| canonical-varint discipline at `qlab-cbserver/src/codec.rs:257` and `qlab-devnet/src/body.rs:284,857` | ⬜ not yet read — stage 3 |
| `main`'s suite baseline 1186 (PR #244's record) | ⬜ not yet reproduced — stage 4 |
| role codes 0…13 used, 14 and 15 free | ✅ `narrow.rs:167-202` |
| `NARROW_WIDTH` = 617 unfeatured, 620 featured | ✅ `narrow.rs:160-162` |
| option 4's measured shape exists only on QUM-62's unpushed branch | ✅ no `claude/qum62-*` on the remote; numbers come from the issue thread alone |
| slot 0 is a real spend, kept so by `q69_dv_cannot_make_slot_0_a_dummy` | ✅ test exists in `narrow.rs`'s latch block |

### 🔴 Two conflicts, raised on #219 (issuecomment-5173655416) and not resolved by me

1. **Stage 1 names the two-perm form; #219 ruled the one-perm form.** Stage 1 says
   `ρ′_j = H(nf_0 ‖ j)`, 83 → 85 perms. The ruling
   ([#219 issuecomment-5157679043](https://github.com/qumbra-labs/qumbra-lab/issues/219#issuecomment-5157679043))
   is titled **"Decision: the one-permutation form"** — `ρ′_0 = nf_0`, `ρ′_1 = H(nf_0 ‖ D_P|1)`,
   83 → **84** perms — chosen because output 0 keeps (i)'s *structural* uniqueness instead of
   dropping to 2^128, and because it spends **one** of the two free role codes rather than both.
   Stage 1's text is the pre-ruling proposal carried from #215. **Building the one-perm form.**
   The gate's byte figure survives: QUM-62's `opt4a` arm (bank + 1 perm) is 84 perms / width 636 /
   **147,813 B**, the same bytes as `opt4`.

2. **Width 636 is the inert probe's geometry and a real bank cannot reach it.** QUM-62's 19
   columns were a bank that *"duplicates equality bank 2's legs verbatim"* plus perms that were
   *"inert `ROLE_ANK` slots"* — so it paid for **no new role selector** and **no new injection
   class**. A real option 4 pays for both. Predicted 22 columns (below), i.e. width 639 /
   148,161 B feature-off — **arithmetic over the 116.0 B/column slope, not a measurement.**
   Reporting the baseline column-by-column against 617 rather than matching a number.

---

## Stage 1 — the construction, as designed before building

### What has to be true

- `ρ′_0 = nf_0` — `nf_0` is `PV_NF1`, a public value, and also the `NF_0` perm's digest.
- `ρ′_1 = H(nf_0 ‖ D_P)` — one new permutation.
- Both must be **bound**, not merely equal: `msg_acmout` takes ρ′ from witness lanes `W5..8`
  (`narrow.rs:654-662`, *"all witness"*), which is exactly #215's faerie-gold finding.

### The obstacle, and why it is the latch's obstacle again

The two output perms share `ROLE_ACMOUT`, so every gate of the form `bnd · sel(ACMOUT)` fires at
**both** — the same thing that stopped `ROLE_BANCHOR` from expressing "the second anchor bind"
(#219 correction 2). Under the one-perm form the two outputs' ρ′ have *different sources*
(`nf_0` vs the ARHO digest), so the bank must tell them apart.

Answer, same as the latch's: a **program-driven span marker** off gates that already exist.
`BGC_OFF+3 = gperm · sel(BCM1)` and `BGC_OFF+4 = gperm · sel(BCM2)` are existing bind-close
gates (`narrow.rs:733-738`), and `BCM1`/`BCM2` are **distinct role codes** — so

```rust
next[M] = M · (1 − BGC[bcm2]) + BGC[bcm1]      // degree 2, one transition constraint
```

is high across exactly output 1's `ACMOUT → BCM2` span and nowhere else, pinned to 0 at row 0.
The prover chooses nothing about it.

### Program order

`… BANCHOR_1 → ACMOUT_0 → BCM1 → ARHO → ACMOUT_1 → BCM2 → BAL → END` — 84 perms.
`ARHO` sits immediately before `ACMOUT_1`, so `ACMOUT_1`'s boundary rows carry the ARHO digest
as `a[0..4]`. Program order is verifier-fixed (`narrow.rs:501-506` pins the ring at row 0 and
`verifier.rs` overwrites only `.pvs`), so this is not a prover choice.

### `ROLE_ARHO` = 14

Full-state override, `msg_ank`'s shape with a different domain constant:

```
lane 0..3   = W0..3      nf_0, bound by the third bank (window A)
lane 4      = sel(2)     D_P = 1 << 3 — the next free iota position, no new periodic column
lane 5      = sel(0)     pad10*1 start at bit 320
lane 16     = u63        pad terminator at bit 1087
```

`D_P` is **load-bearing, not hygiene**: without it, `ρ′ = H(nf_0 ‖ pad)` and
`nk = H(sk ‖ D_N ‖ pad)` are the same function, and an attacker setting `sk := nf_0` — a public
value — obtains `nk == ρ′`. That sentence goes in the code.

### The third bank — one accumulator, three windows

| window | positive leg | negative leg | close | forces |
|---|---|---|---|---|
| A | `+a[0..4]` at `bnd · sel(BNF1) · ep` (= `nf_0`) | `−W0..3` at `bnd · sel(ARHO) · ep` | `gperm · sel(ARHO) · ep` | ARHO absorbs the **real** `nf_0` |
| B | `+W5..8` at `bnd · SE[acmout]`, `M = 0` | close target is `PV_NF1` | `gperm · SE[acmout]` | `ρ′_0 = nf_0` |
| C | `+W5..8` at `bnd · SE[acmout]`, `−a[0..4]` gated by `M` | — | `gperm · SE[acmout]` | `ρ′_1 = ARHO digest` |

Windows B and C share one close expression, `M` switching the target:

```rust
assert_zero( close · ( acc_j − (ONE − M) · pv(PV_NF1 + j) · ep ) )   // degree 3
```

### Predicted column cost — REASONED, TO BE MEASURED

| | cols | why |
|---|---|---|
| third accumulator | 16 | 4 lanes × 4 z-chunks, as banks 1/2 |
| bank gates | 3 | pos, neg, close — the file materializes one column per leg per bank |
| `M` span marker | 1 | |
| `sel(ROLE_ARHO)` | 1 | `NSEL` 13 → 14 |
| `inj(ROLE_ARHO)` | 1 | `INJ_OFF` 5 → 6 |
| **total** | **22** | width 617 → **639**; `145,609 + 22 × 116 = 148,161 B` |

**Degree:** the new selector is `pair · pair`, degree 4 — the same shape as the 13 that already
set `main`'s maximum (histogram `{1: 207, 2: 511, 3: 142, 4: 13}` at `d16ffd5`). The marker
transition is 2, the accumulations 3, the close 3. **Nothing exceeds 4, so quotient chunks stay
4.** If that is false, the 116 B/column line does not apply and stage 1 stops.

### 🟢 Stage 1 — MEASURED (2026-08-04, rig lock held for every run)

**Rig:** Apple M5 Max, 18 cores, 36 GiB, AC, macOS 26.5.2, Plonky3 0.6.1 pinned via
`Cargo.lock`. Config: the consensus lane only — `b16/q21/g22/fp16/a16` at `LOG_HEIGHT = 18`.

| quantity | base | latch | **option 4** | **both (the mint)** |
|---|---|---|---|---|
| `trace.width()` | 617 | 620 | **640** | **643** |
| columns over base | — | +3 | **+23** | **+26** |
| perms | 83 | 83 | **84** | **84** |
| rows used / height | 254,976 / 2^18 | same | **258,048 / 2^18** | same |
| 🔴 max constraint degree | **4** | **4** | **4** | **4** |
| 🔴 quotient chunks | **4** | **4** | **4** | **4** |
| symbolic constraints | 873 | 880 | **930** | **937** |
| degree histogram | `{1:207, 2:511, 3:142, 4:13}` | `{1:208, 2:500, 3:159, 4:13}` | `{1:207, 2:531, 3:177, 4:15}` | `{1:208, 2:520, 3:194, 4:15}` |
| **proof bytes**, bincode-fixed | **145,609** | **145,609 + 348 = 145,957** | **148,277** | **148,625** |
| runs identical | 5/5 | 5/5 | **5/5** | **5/5** |

- **The 116.0 B/column slope holds, third independent time.** 23 × 116 = 2,668 → 148,277.
  26 × 116 = 3,016 → 148,625. Predicted before the run and reproduced to the byte.
- **The added permutation costs zero bytes**, as #219's six-arm measurement said it would.
- 🔴 **The hard stop is clear**: degree 4 and 4 chunks in **all four** feature sets, read
  off `p3_air::symbolic::get_max_constraint_degree`, not counted by hand. The deg-4
  population goes 13 → 15 and both additions are named in the test.
- **The base row reproduces PR #239's census at `d16ffd5` exactly** (873 and the same
  histogram), which is what makes the featured rows comparable to it.
- 🔴 **148,625 B is the mint's number, and it is a MEASUREMENT on one tree.** The sum
  148,161 B was never reachable: it assumed the probe's 19 columns.

### 🔴 Column accounting over 617 — the gate's item (a), every column named

Test-locked in `q69_trace_width_is_read_off_the_matrix`, which asserts the sum against the
matrix, so a future column has to add its row here to stay green.

| # | column | why |
|---|---|---|
| 1 | `sel(ROLE_ARHO)` | `NSEL` 13 → 14 — a materialized role selector |
| 1 | `inj(ROLE_ARHO)` | `NINJ` 5 → 6 — a full-state override is its own injection class |
| 1 | `SE_RHO = (arho + acmout)·ep` | `NSE` 6 → 7 — the third bank's window selector |
| 1 | `OM` | the output-1 span marker |
| 3 | `EG3` | pos, neg, close (close doubles as reset) |
| 16 | `EQ3` | the third accumulator, 4 lanes × 4 z-chunks |
| **23** | | 617 → **640** |

**Against the stage-0 estimate of 22, the missing row was `SE_RHO`** — the estimate counted
the bank's three gates but not the ep-gated selector those gates are built from. Banks 1 and
2 get theirs free only because `nf`/`arkm`/`acm` already had SE entries for other reasons.

### What the construction ended up being, vs the stage-0 design

The stage-0 sketch had **six** bank gates (a separate positive source at `BNF1`, its own
ARHO window, and separate closes). Two simplifications collapsed it to three:

1. **The close target is switched by `M` instead of by a second close gate** — `assert_zero(
   close · (acc − (1 − M)·PV_NF1·ep))` serves all three windows, because ARHO's close and
   ACMOUT_0's both want `PV_NF1` and only ACMOUT_1's wants zero. That in turn moved the
   marker's span: `M` is set at **ARHO's** close (not `BCM1`'s) and cleared at `BCM2`'s, so
   ARHO itself sits *outside* the span and reads the public target.
2. **ARHO takes `nf_0` in `W5..8`** — the same witness lanes ACMOUT takes `rho'` in — so one
   positive leg gate serves both roles. Window A stopped needing a positive source at `BNF1`
   at all: it closes ARHO's own witness against `PV_NF1`, which is public.

### Tests owed at stage 1 (the ruling's items, not optional)

- the tamper test in `narrow.rs:2133`/`:2141`'s pattern — a flipped ρ′ bit is refused
- `ρ′_0 = nf_0` and `ρ′_1 = H(nf_0 ‖ D_P)` recomputed against `reference::keccak_f`
- **the named dependency**: slot 0 is a real spend by construction, so `nf_0` is a sound
  uniqueness source — a test that says so and breaks if the latch's
  `q69_dv_cannot_make_slot_0_a_dummy` property is lost
- `nf1 == nf2` no longer yields `ρ′_0 == ρ′_1` (the accident #215 asked to have removed rather
  than documented)

### 🟢 Tests as built — 10 new, and both mutation directions checked

`-p qlab-air`: 19 unfeatured / 27 latch / **29 option 4** / **37 both**.
`-p qlab-consensus`: 3 / 5 / 3 / **5**, all serial (`--test-threads=1`).

| test | what it pins |
|---|---|
| `q215_rho_derivations_match_the_reference` | both seeds recomputed against `reference::keccak_f`, not against the circuit that made them |
| `q215_domain_p_separates_arho_from_ank` | 🔴 `D_P` is load-bearing: `sk := nf_0` does **not** yield `nk == ρ′`, executed rather than argued |
| `q215_full_bucket_satisfies_with_derived_rho` | the emitted bucket proves; `ARHO` is immediately before output 1's `ACMOUT`; exactly one `ARHO` |
| `q215_output_0_rho_is_bound_to_nf_0` | a **complete forgery** — prover-chosen seed *with the matching `cm` published* — is refused |
| `q215_output_1_rho_is_bound_to_the_arho_digest` | same for output 1, plus the near miss `ρ′_1 := ρ′_0` |
| `q215_arho_absorbs_the_real_nf_0` | 🔴 the one most likely to be missed — a forged `nf_0` inside ARHO, with output 1's seed *and* commitment moved to match, is refused by window A alone |
| `q215_marker_span_is_exactly_output_1` | `M` asserted on all 262,144 rows, both edges pinned separately, exactly one rise and one fall |
| `q215_equal_nullifiers_cannot_equalise_the_seeds` | the `nf1 ≠ nf2` accident is **gone**, not pinned: two buckets differing only in input 1 publish identical output commitments |
| `q215_two_identical_output_notes_are_unsatisfiable` | faerie gold direct — two outputs at the same opening, duplicate `cm` declared honestly |
| `q215_uniqueness_inherits_from_slot_0_being_a_real_spend` | 🔴 **the named dependency**: slot 0's full real chain asserted position by position, cross-referencing `q69_dv_cannot_make_slot_0_a_dummy` |

🔴 **Why the forgery shape matters, since it is the difference between a real tamper test and
a decorative one.** The first draft flipped one bit of a `ρ′` witness — and that test passes
on `main` too, because the `PV_CM` bind catches the changed commitment. It says nothing about
whether the seed is bound. Every tamper test here therefore **republishes the commitment that
opens at the forged seed**, so the ACMOUT injection, the `PV_CM` bind and the balance are all
satisfied and the third bank is the only thing that can refuse. Each also asserts that the
**honest** seed verifies through the same helper, so a broken helper cannot make it vacuous.

**Mutation-checked in both directions** (the #106 discipline):

| mutation | expected | observed |
|---|---|---|
| third-bank close constraint deleted | the four soundness tests go green-to-red | **4 failed**, honest bucket still passes |
| `(1 − M)` replaced by `(1 − 0)` in the close | the honest bucket itself must fail | **`q215_full_bucket_satisfies_with_derived_rho` FAILED** — `M` is load-bearing, not decoration |

### 🟡 Found on the way, fixed here

`q69_dummy_proof_verifies_and_is_size_indistinguishable` hard-coded `145_957`, so it broke
under `q215-rho + q69-latch` while its actual property (`d_bytes == real_bytes`) held. The
absolute now comes from one `expected_wire_bytes()` table that the wire pin also reads —
a wire change can no longer be half-applied. **Also confirmed by that test: a dummy-slot
proof is still size-indistinguishable from a real one in the combined tree (148,625 B both),
and `build_bucket_dummy1` composes with option 4 for free** because it delegates to
`build_bucket_with_witnesses`.
