# Task book — the mint combination baton: #215 (i)/option 4 + latch-on + #188 (a), one tree, one measured number

**For a CLI builder session, deliberately not Multica** — this baton makes payload and
FROZEN-constant changes by design, which the Multica workspace context is required to refuse.
Your stop-point discipline is THIS document. Branch `claude/mint-combo` off current `main`;
staged commits per stage (builders hit usage limits mid-build; an uncommitted stage is lost
work). **Open a PR at the end and NEVER merge it** — the merge IS the mint ratification and
it is Larry's, through the coordinator.

**Estimates are Claude session-hours.** Whole baton ≈ 4–8 sh; the stage gates below are
designed so a session boundary can fall between any two stages.

## Why these three ride together (the ruling, not a preference)

Ruled on [#219](https://github.com/qumbra-labs/qumbra-lab/issues/219) and
[#188](https://github.com/qumbra-labs/qumbra-lab/issues/188): every one of these changes
moves bytes that sit inside `qumbra_node::genesis::CONSENSUS_WIRE_BYTES`
(`crates/qumbra-node/src/genesis.rs:72`, FROZEN v1.0, serialized into the genesis file,
therefore inside the genesis hash) or inside the body encoding a genesis net must agree on.
Each alone costs a re-mint; together they cost one. And the target constant **must be a
measurement on one tree**: every combined figure quoted anywhere (148,161 B; the stage-0
arithmetic’s ~148,509 B at width 642) is slope arithmetic or a cross-tree sum, and neither
mints anything (coordinator ruling, #219, 2026-08-03; gate amendment 2026-08-04). **The
stage-4 measured figure is the only number that exists.**

## Mandatory reading before any code (stage 0, ~0.5 sh)

Read the **threads, not the bodies** — several of these issues' bodies carry premises their
own threads later corrected:

1. [#219](https://github.com/qumbra-labs/qumbra-lab/issues/219) — the whole thread: the
   dummies↔(i) exclusivity, QUM-62's six-arm measurement (perms cost **zero** bytes; the
   third equality bank costs **+2,204 B**; option-4 arm = 85 perms / width 636 /
   **147,813 B**, 5/5 identical), and the coordinator's mint-sequencing comment.
2. [#215](https://github.com/qumbra-labs/qumbra-lab/issues/215) — the faerie-gold finding
   (ρ′ is a free witness: `narrow.rs` "all witness" on the output commitment) and the
   coordinator's self-correction (the spendability cost was misattributed; what stands is
   the exclusivity, resolved by option 4).
3. [#188](https://github.com/qumbra-labs/qumbra-lab/issues/188) — the option (a) DECISION
   comment (2026-08-02): 56 B/note AEAD payload (`value ‖ rseed`), (d) rejected for
   spending the unresolved `clue` reservation and breaking a consensus lock, NOT for bytes.
4. `qumbra-design/discovery-on-the-consensus-wire.md` — the body-preimage spec: per-tx
   placement, reuse of the **ratified compact bytes**, `discovery_len` prefix, binding by
   commitment equality, coinbase excluded, **canonical varints before any preimage work**.
5. [PR #239](https://github.com/qumbra-labs/qumbra-lab/pull/239) — the latch construction
   as merged (3 cols, feature `q69-latch`, default off), its acceptance table, and the
   coordinator's 2-col decline (**do not build the 2-col variant**).
6. [PR #242](https://github.com/qumbra-labs/qumbra-lab/pull/242) §"first: the task book's
   citations, checked" — the reporting shape this baton owes back.

## What already exists — verify, do not rebuild

| thing | where | state |
|---|---|---|
| the latch, 3 cols, tested | `crates/qlab-air/src/narrow.rs` behind `q69-latch` (`qlab-air/Cargo.toml:15`, forwarded by `qlab-consensus/Cargo.toml:18`) | merged, default off |
| option 4's measured shape | QUM-62's instrument branch — **never pushed, does not exist remotely** | numbers only; rebuild from spec |
| #188 infrastructure 1/4–3/4 | body preimage (#193), discovery serving (#202), recipient-finds-output (#214) | merged |
| canonical-varint discipline | e.g. `qlab-cbserver/src/codec.rs:257`, `qlab-devnet/src/body.rs:284,857` | merged — the wire spec's precondition is discharged; cite the tests in your report |
| compact framing | golden-locked (`wallet-interop` §2) | MUST NOT move |
| the frozen constant | `qumbra-node/src/genesis.rs:72` (`145_609`), consumed at `:202`; wire pin test `qlab-consensus/src/lib.rs:282` area | changes ONLY in stage 5 |
| wallet scan path | `qumbra-wallet` (`scan_over` / `light_client_scan`) | merged; its PR #244 names "my key over HTTP against a net that paid it" as **this baton's** demonstration |

## Stages — ordered so every measured delta has one cause

**Stage 1 — the one-permutation form (ρ′ derivation + third equality bank), feature OFF
(~1.5–2.5 sh).**

> **Corrected 2026-08-04** ([ruling](https://github.com/qumbra-labs/qumbra-lab/issues/219#issuecomment-5173677816)).
> This stage originally said `ρ′_j = H(nf_0 ‖ j)` / two perms / a 147,813 B calibration
> gate — that was #215's **pre-ruling** option-4 paragraph, and the gate's baseline was
> QUM-62's probe bank, which paid for neither a role code nor an injection class. Both
> were caught at stage 0 by the first builder, before any code. Original text preserved
> in git history; the corrected stage follows.

Build per #219's **decision comment** ("the one-permutation form"): `ρ′_0 = nf_0`
(structural — (i)-strength inherited from the checked double-spend rule), `ρ′_1 =
H(nf_0 ‖ D_P|1)` via a new **`ROLE_ARHO`** full-state-override permutation (83 → 84, one
role code spent — reusing `ROLE_ANK` *is* the collision `D_P` exists to close), plus the
third equality bank binding both output commitments' ρ′ lanes to their two **different**
sources (a span marker off the existing `BGC[bcm1]`/`BGC[bcm2]` distinguishes the two
ACMOUT perms, same shape as the latch's BANCHOR answer). Slot 0 is a real spend by
construction (the latch's `q69_dv_cannot_make_slot_0_a_dummy` keeps it so), which is what
makes `nf_0` a sound uniqueness source — **name this dependency in a test**, see stage 4.
**Gate (amended):** (a) account for the width delta over 617 **column by column, every
column named** (the stage-0 arithmetic says 22 — selector, injection flag, marker, 3 bank
gates, 16 accumulator, vs the probe's 19 — if the count differs, say which row); (b)
measure proof bytes 5/5 byte-exact and report them *beside* the slope arithmetic
(116.0 B/col), never gated on it; (c) 🔴 **hard STOP if the quotient degree or chunk
count moves** — that is a different tree and the slope does not apply to it.

**Stage 2 — the latch becomes unconditional (~0.5 sh).**
Delete the `q69-latch` cfg arms (both crates' feature decls, the `cfg` blocks, the
feature-aware branches of the wire-pin test). Rationale (coordinator ruling): a dead
config knob on a consensus circuit is a mis-built-binary hazard, and the off-shape is
unreachable after the mint. The unfeatured wire pin moves to the measured stage-2 figure —
expected 148,161 B (sum), **measured value wins and is the headline**. Gate: quotient
degree still 4; `dv=0` still the unchanged 2×2 (PR #239's leak test carries over).

**Stage 3 — #188 (a) as amended: relocate the payload, do not shrink it (~1–2 sh).**

> **Corrected 2026-08-04** ([amendment](https://github.com/qumbra-labs/qumbra-lab/issues/188#issuecomment-5175013679)).
> The 56 B form's premise failed one scanner-class down (an `Ivk` deliberately cannot
> derive `rkm` — issue #32; `/v1/compact` carries no nullifier, so a light client cannot
> derive ρ). The plaintext stays 104 B (120 B with tag).

The full 120 B AEAD payload, relocated into the committed discovery region per the
accepted placement position (`group_contents ‖ payloads`, fixed-width per entry, D4
order; `/v1/compact` projects only the prefix). `scan` verifies `cm` against the entry
for every scanner class, and a full-body observer cross-checks payload-ρ against the
derived ρ. This changes **body bytes, not proof bytes** — assert that: the stage-2 proof
figure must not move in stage 3. Golden compact framing must not move either; if either
moves, STOP.
Then close the loop PR #244 left open: **an end-to-end test where a wallet's own key,
paid on a devnet, finds its payment through `scan` over HTTP** — value and rseed arriving
via the payload, ρ read off `nf_0` per option 4.

**Stage 4 — the measurement battery + the suite (~1 sh).**
- Full bar, rig-locked: `scripts/rig run -- cargo test --release --workspace -- --test-threads=1`;
  reconcile out loud against `main`'s baseline (1186 as of PR #244's record) ± your adds.
- Proof bytes 5/5 identical; width; perms; degree histogram; quotient chunks (must stay 4).
- Adversarial set, minimum: tampered ρ′ (≠ `H(nf_0‖j)`) refused in-circuit; the
  **dummy-composition seam** — slot 1 dummy (`dv=1`), outputs' ρ′ still derived from the
  real `nf_0`, proof verifies AND a forged ρ′ under the same dummy shape is refused;
  faerie-gold direct: two outputs forced to identical `(value, rkm, ρ′, rseed)` must be
  unsatisfiable; payload tamper → commitment-equality binding refuses the body.
- Peak RSS via `/usr/bin/time -l` on the consensus prove — report, not gate (envelope is
  the phone story, not this baton).

**Stage 5 — genesis, then STOP (~0.5 sh).**
Update `CONSENSUS_WIRE_BYTES` to the **stage-4 measured figure**, regenerate the lab
genesis fixture, reproduce its hash twice, update the params-audit row. Commit, open the
PR with the full report (PR #242's citation-check table shape), and **stop — the merge and
the T0 re-mint/redeploy are the ratification step and belong to the coordinator, Larry,
and T-ops respectively.** Whether the deployed net rolls immediately is not this baton's
question.

## Standing rules

- Rig: every heavy run through `scripts/rig run --`; see `docs/the-rig.md`.
- If you ask on an issue and nobody answers by the time you are blocked: take the smaller
  action, mark it separable, say in the PR that you asked and proceeded.
- Report what you did NOT verify, most-likely-to-break first — the reports this repo
  trusts all do.
