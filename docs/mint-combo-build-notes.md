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

---

## Stage 2 — both changes unconditional

### What "the latch becomes unconditional" had to mean

The stage title names only the latch, but the figure it names — *"the unfeatured wire pin moves
to the measured stage-2 figure"* — is the **combination** (the sum it quotes, 148,161 B, is
19 + 3 columns). With only the latch unconditional the unfeatured pin would be 145,957 B. So
stage 2 deletes **both** feature gates: `q69-latch` and `q215-rho`, both feature tables, all 50
`cfg` sites, and the feature-aware branches of the wire pin. One tree, one number, no knob.

Rationale as ruled: a dead config knob on a consensus circuit is a mis-built-binary hazard, and
the off-shape is unreachable after the mint.

**How the transformation was verified rather than trusted:** the unconditional tree measures
**exactly** what the both-featured tree measured the stage before — 643 columns, 84 perms,
148,625 B, degree 4 / 4 chunks, 937 constraints, 37 `qlab-air` + 5 `qlab-consensus` tests. A
faithless `cfg` strip would have moved one of those.

The wire pin is now one constant, `WIRE_BYTES = 148_625`, read by both the pin and the
dummy-proof size test. The test is renamed `consensus_wire_is_148625_bytes`.

### 🔴 The finding: the M4 aggregation gate verified a shape the prover no longer emits

`crates/qlab-bench/src/m4gate.rs` had **`const TW: usize = 617` as a hard-coded literal, with
nothing tying it to `NARROW_WIDTH`.** `GateShape::narrow()` carried the same literal a second
time. The only assertion on it, `assert_eq!(n.tw, TW)`, checks the gate against *itself*.

PR #239 named this hazard and left it: *"Aggregation. A 620-column trace changes the rung-1
leaf's input shape. Untouched and unconsidered."*

At 643 columns it stopped being theoretical. **64 `m4gate` tests failed**, all on the same
assertion:

```
assertion `left == right` failed: obs flush 2 block count
  left: 154   right: 148
```

Flush 2's challenger message opens two `tw`-length zeta groups plus the quotient group, so the
real proof absorbs 154 keccak blocks where the shape table — built from `tw = 617` — said 148.

**Fix, in two parts, both "make it derived":**

1. `const TW: usize = qlab_air::narrow::NARROW_WIDTH`, and `GateShape::narrow()` reads `TW`
   instead of repeating the literal. That took the failures 64 → 3.
2. The remaining three were the *module-level* mirror of the same mistake: `FLUSH_BYTES` and
   `FLUSH_BLOCKS` were literal arrays holding the `tw = 617` answers (`20_032` bytes / `148`
   blocks for F2, the zeta-opening flush). F2 is the only `tw`-dependent entry — it carries
   `2·tw + qw` opened values at 16 bytes each behind a 32-byte digest prefix — so it is now
   written as `32 + 16 * (2 * TW + QW)`, and `FLUSH_BLOCKS` as `FLUSH_BYTES[2] / 136 + 1`.
   At 643 columns those come out **20,864 B / 154 blocks**, which is exactly the number the
   real proof produced.

Everything else downstream (`dup_captures`, the `A*`/`P0R` offsets, `n_shapes_obs`, `qslots`)
was already derived and needed nothing. Two of them provably do not move at all: F2's block
count collapses to 3 in `n_shapes_obs`, and `ceil34(617) == ceil34(643) == 19` keeps `QSLOTS`
at 103. So this is a config correction, not an aggregation redesign.

🔴 **The part worth reporting to the coordinator, not the fix:** the only reason this was ever
caught is that the mint moved the width by enough to break an *unrelated* block count. A
smaller width change would have left the aggregation lane silently verifying a shape the
consensus prover no longer emits — and `assert_eq!(n.tw, TW)` would have stayed green
throughout. The literal is gone and a comment at `TW` says it may never come back.

### 🔴 The faucet: a free witness that was the finding, and a seam assert that was asleep

`qlab-faucet`'s three acceptance tests failed with `DiscoveryDoesNotBind { index: 0, expected:
2, got: 2, first_mismatch: Some(0) }` — the count right, the first commitment wrong. The faucet
drew ρ from the CSPRNG:

```rust
// ρ/rseed are fresh CSPRNG draws — ρ is what the nullifier binds, so a repeat
// would make the change note unspendable behind an already-published nullifier.
let grant_rho = rand_lanes(rng);
```

That comment is a fair description of the pre-#215 world, and **that line is #215's finding
itself** — *"the only path that builds a note for a third party"* (`grant.rs:313-318`, quoted in
the issue body). It is now `derive_output_rho(&nf0, j)` with `nf0 = derive_input(&spend[0]).1`,
computed before the build from the same nullifier the circuit will use. Uniqueness stops being
probabilistic and becomes inherited from the double-spend rule.

🟡 **And the guard for exactly this existed and was asleep.** Two lines below, `grant.rs` had:

```rust
debug_assert_eq!(inst.cm_out[0], grant_note.commitment(), "grant cm seam");
```

`debug_assert!` — so in the **release-mode** acceptance run (which is the bar) it compiles to
nothing. The seam between "the note a recipient will open" and "the commitment the chain will
hold" was checked only in debug, so the break surfaced three call layers away as a consensus
error instead of at the point of construction. Both are now `assert_eq!`; two keccak-f
permutations per grant is a fair price. **Worth generalising:** a `debug_assert` on a
cross-layer agreement is a comment, not a check, because this repo's acceptance bar is
`--release`.

### 🟡 A process finding about the acceptance bar itself

CLAUDE.md's bar is `cargo test --release --workspace -- --test-threads=1`, and **cargo stops
after the first failing test binary.** A change with a wide blast radius therefore reveals its
sites one crate at a time, at ~20 minutes of rig per pass. This baton spent **four** passes
enumerating what one pass with `--no-fail-fast` would have listed at once:

| pass | revealed |
|---|---|
| 1 | 64 × `m4gate` (the `TW` literal) |
| 2 | `m5note::commitment_matches_qlab_air`, `m4gaterec` census, 2 × asm census |
| 3 | `qlab-demo` E2E — *the recipient cannot spend what they received* |
| 4 | `qlab-disclosure::packing::note_commitment_matches_build_bucket` |

Nothing was wrong with any individual run and every number reported was honest. But **the bar
as written optimises for "is it green" and this baton needed "what is red"**, and those want
different flags. Worth considering `--no-fail-fast` for the enumerate phase, with the
unmodified command as the final acceptance run — the suggestion is the coordinator's to take,
and it is recorded here rather than acted on unilaterally because the bar's exact wording has
cost this repo twice already (`PR #23`, `PR #166`).

Also worth naming: **three separate crates carry the same `note_commitment` ↔ `build_bucket`
cross-check** (`qlab-note`, `qlab-bench::m5note`, `qlab-disclosure::packing`). All three are
good tests and all three broke for the same reason. That is redundancy doing its job, not
duplication to clean up — but a reader who fixes one should know there are two more.

### Other wire-dependent pins moved (not the frozen constant)

| site | was | now |
|---|---|---|
| `qlab-faucet/tests/acceptance.rs` — `plan.proof_bytes` | 145,609 | 148,625 |
| `qlab-faucet/src/grant.rs`, `qlab-demo/src/prover.rs`, `qumbra-node/src/verifier.rs` | doc refs to 145,609 | 148,625 |
| `qlab-consensus` `LOG_HEIGHT` doc | "83 perms" | "84 perms" |

`qumbra_node::genesis::CONSENSUS_WIRE_BYTES` is deliberately **untouched here** — that is
stage 5, with the genesis regeneration and the hash reproduced twice.

---

## Stage 3 — #188 (a), the discovery payload — DESIGNED, NOT BUILT

Written down before building so a session boundary here costs nothing. Everything below is a
source read at this branch's HEAD, with the design position stated.

### What (a) actually changes

The note plaintext is `value ‖ rkm ‖ ρ ‖ rseed` — `NOTE_PLAINTEXT_LEN = 104`
(`qlab-note/src/note.rs`). Under option 4 two of the four fields stop needing transmission:

- `rkm` is the recipient's own key material — never needed sending, and it was in there anyway;
- **`ρ` is now public** — `ρ′_0 = nf_0` is `PV_NF1`, `ρ′_1 = H(nf_0 ‖ D_P)`, and the index is
  fixed by position, so any observer computes both from block data.

So the payload becomes `value(8) ‖ rseed(32)` = 40 B, plus the 16-byte ChaCha20-Poly1305 tag =
**56 B/note**, down from 120. That is the whole of (a)'s arithmetic, and it is why (i) *"pays
for more than half of (a)'s cost"*.

### 🔴 Where the payload goes — the position, with the reason

| constraint | source | consequence |
|---|---|---|
| golden compact framing must not move | task book stage 3; the 1177-B vector is a **`/v1/compact` serving response** (`codec.rs:497`) carrying `version ‖ n_blocks ‖ height ‖ n_groups ‖ tx_index ‖ n_recipients ‖ ct ‖ n_outputs ‖ 2 entries` and **no payload** | the payload may **not** enter `CompactEntry` or the group-contents encoding |
| "(a) does not touch `CompactEntry` at all" | #188's decision comment | same |
| reuse the ratified compact bytes | `discovery-on-the-consensus-wire.md` D2 | the committed prefix stays byte-identical |
| the committed region contains **no varint at all** | `compact.rs:270-275` — every field fixed-width or single-valued, so it *"admits exactly one byte string per logical group by construction"* | whatever is appended must be **fixed-width** |

**Position: the body's discovery region becomes `group_contents ‖ payloads`,** with one fixed
56-byte payload per entry in D4's order (recipient-major, then per-output). `/v1/compact`
continues to project only the `group_contents` prefix, so the golden serving vector is
untouched; the payloads are committed and therefore cannot be withheld by a light server,
which is the whole point of option 3.

🟢 **The no-varint property survives, and that is not luck — it is (a)'s doing.** A 56-byte
payload is fixed-width precisely *because* ρ and `rkm` left it; the 104-byte plaintext would
have been fixed-width too, but (d)'s `clue`-slot variant would not. The entry count is already
carried by `n_outputs`, so no length prefix is needed and D6's canonicity question still never
gets a chance to matter inside the preimage.

### 🔴 The finding that says why stage 3 is not optional, and the suite found it

`qlab-demo`'s `end_to_end_payment_loop_holds_all_invariants` failed with:

```
spend input's note commitment must be a leaf of the live tree
```

Alice pays Bob, Bob **scans and detects** his note, and then **cannot spend it.** The reason is
the whole of #188 (a) in one sentence: Alice encrypted a note at a ρ *she chose*, `build_bucket`
committed the note at the ρ it *derives*, so the note Bob reconstructs from the payload has a
commitment that is not in the tree.

**This is the loop PR #244 left open, failing for real rather than in the abstract** — and it is
the strongest argument that the payload contents and the derivation are one change and not two.
The interim fix in stage 2 is minimal and deliberately not stage 3's: Alice now *computes* the
derived seed (she knows `nf_0` — it is `derive_input(&a_inputs[0]).1`) and sends the right value
instead of the wrong one. The payload still carries ρ. **Stage 3 removes ρ from the payload
entirely and has Bob derive it**, which is where the 120 B → 56 B saving actually lands.

### The API ripple, named

`Note::from_plaintext` can no longer reconstruct a `Note` on its own — it yields
`(value, rseed)`, and the recipient must supply `rkm` (their own) and `ρ` (derived from the
transaction's `nf_0`). So `scan` gains those inputs, and the seam runs through
`qlab-note::scan` → `qlab-cbserver` → `qlab_node::rpc` → `qumbra-wallet` / `qlab-faucet` /
`qlab-demo`. **Two tests already mark this seam** and were updated in stage 2 rather than
worked around: `qlab-note::note::commitment_matches_qlab_air_build_bucket` and
`qlab-bench::m5note::commitment_matches_qlab_air`.

### The gates stage 3 must clear

- **Proof bytes must not move**: 148,625 B before and after. (a) is body bytes, not proof bytes.
- **The golden compact vector must not move** — 1177 B and the same Keccak-256 digest.
- Then PR #244's open loop: **a wallet's own key, paid on a devnet, finding its payment through
  `scan` over HTTP** — `value` and `rseed` from the payload, ρ read off `nf_0`.

---

---

## 🟢 Stage 4's interior gate — MEASURED (coordinator item 3, 2026-08-04)

`scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench m4assembly --lane b2 ac` at
width 643, twice.

| | run 1 | run 2 | D3 baseline (pre-mint) |
|---|---|---|---|
| **peak memory footprint** | **19.75 GB** | **20.80 GB** | 19.75 / 20.42 GB |
| max RSS | 17.73 GB | 18.66 GB | — |
| leaf L / R proof | 839.2 KB | 839.2 KB | 839.2 KB |
| interior root proof | 1.65 MB | 1.65 MB | 1.65 MB |
| interior rows | 2^19 | 2^19 | 2^19 |
| swaps | 0 | 0 | 0 |

**No breach: worst sample 20.80 GB against the 32 GB envelope — 35 % margin.** The ≥2× STOP
would need 64 GB.

🔴 **The structural result matters more than the footprint.** Neither level's proof size or
height moved *at all* — byte-identical to #24 D3's record. The 26 columns grew the leaf gate's
row consumption (F2 148 → 154 blocks, which is what broke the 64 tests) **without crossing
either power-of-two boundary**, and memory follows heights, not cells.

🟡 **The +0.38 GB on the high sample is not attributable.** D3's own two runs spread 0.67 GB on
a byte-identical tree and my low sample reproduces D3's low sample exactly; both metrics moved
together between my runs. Read as unchanged within the instrument's spread. A real delta needs
paired interleaved runs against a pre-mint binary in one session — not done.

**Not verified: the b4 interior fallback lane** (31.21 GB pre-mint, ~2.5 % margin — the tight
one). One more run; not taken.

---

## Stage 3's last item — the wallet-binary E2E (Q2) — DESIGNED, NOT BUILT

Scope expansion approved on #219 (2026-08-04): the deliverable is *the product*, not the
machine. Recorded here so the next session starts from a design.

### Why the existing tests do not discharge it

`qumbra-wallet/tests/acceptance.rs`'s scan test says so itself: *"one scan integration over the
reference devnet fixture, **in-process via `scan_local`** — the same function the HTTP path runs,
over a different fetch"*, and it scans with **`devnet.our.dk`** — the fixture's own key, not a
key `keygen` produced. So it proves `scan_local` works. It does not exercise the seed →
diversifier → allocated-index → `diversified_keypair` path that a user's wallet actually walks,
and that path is the one PR #244 wanted evidence for.

### The shape to build

The harness already exists — `BIN = env!("CARGO_BIN_EXE_qumbra-wallet")` and `run(args, stdin)`
at `acceptance.rs:18-40`. Four steps:

1. **`keygen --dir D`** through `run()`. Take the printed `address [0]`; the wallet dir now holds
   the seed and `allocated = [0]`.
2. **Pay that address on a devnet.** The crux, and the only genuinely new work: the devnet
   fixture must encrypt to the *wallet's* `ek`, not its own. `WalletDir::open(D)` →
   `wallet.diversified_keypair(&wallet.diversifier_at_index(0)).ek` gives it; the note must be
   built at the **derived** seed (`derive_output_rho`, issue #215 (i)) or it will not recompute.
   `Devnet::from_parts` (used by `qlab-demo::scenario`) is the assembly seam.
3. **Serve it over HTTP.** `qlab-cbserver`'s test server + `handle.base_url()`, the pattern
   `client.rs`'s tests use.
4. **Run the binary**: `scan --dir D --url <base_url> --to <tip>`. Assert the value is visible in
   the rendered report **and** that the honest-reporting discipline holds — `UNAVAILABLE` absent,
   completeness reported, no partial totals (`view.rs`'s existing vocabulary).

### The trap to avoid

`scan` seeds its decoy RNG from the OS CSPRNG (`main.rs:151-153`), so the run is **not
deterministic**. Assert on the value and the discipline tokens, never on exact decoy-dependent
output.

## Where this baton stands

| stage | state |
|---|---|
| 0 — mandatory reading + citation check | ✅ committed; both conflicts raised, ruled, task book corrected (PR #251) |
| 1 — option 4, the one-permutation form | ✅ committed, measured, gate cleared |
| 2 — both changes unconditional | ✅ committed; aggregation-lane literals fixed; full bar running |
| 3 — #188 (a), the discovery payload | 🟡 **relocation DONE and green (1208/0/1); ρ diagnostic DONE; the wallet-binary E2E is designed above, not built.** Previously blocked — resolved by the #188 amendment. Historical note follows: **BLOCKED on #188's premise, not on the design.** Placement ratified and built against; but (a)'s "rkm is the recipient's own key material" is false for an `Ivk`, and `/v1/compact` carries no nullifier so a light client cannot derive ρ. Two findings reported on #219; payload core preserved on `claude/mint-combo-stage3a-wip` (`186d15f`, does not compile by design) |
| 4 — measurement battery + the suite | 🟡 proof/width/degree/census done and test-locked; **the interior-prove gate is measured and clear (above)**; still owed: the dummy-composition adversarial case, prove time, the b4 interior fallback lane |
| 5 — genesis + `CONSENSUS_WIRE_BYTES` → 148,625 | ⬜ not started; the four other break sites are already moved (stage 2), so what remains is the constant, the fixture, the hash reproduced twice, and the params-audit row |
