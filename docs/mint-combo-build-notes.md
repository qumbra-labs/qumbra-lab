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

### Tests owed at stage 1 (the ruling's items, not optional)

- the tamper test in `narrow.rs:2133`/`:2141`'s pattern — a flipped ρ′ bit is refused
- `ρ′_0 = nf_0` and `ρ′_1 = H(nf_0 ‖ D_P)` recomputed against `reference::keccak_f`
- **the named dependency**: slot 0 is a real spend by construction, so `nf_0` is a sound
  uniqueness source — a test that says so and breaks if the latch's
  `q69_dv_cannot_make_slot_0_a_dummy` property is lost
- `nf1 == nf2` no longer yields `ρ′_0 == ρ′_1` (the accident #215 asked to have removed rather
  than documented)
