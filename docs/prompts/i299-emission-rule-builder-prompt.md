# Builder prompt + task book — the emission-rule baton (lab #299 + #303, one boundary)

**Dispatch**: CLI builder session (this baton is a consensus-layer change and deliberately
does not go to Multica). The opening prompt below is pasted into a fresh session; the task
book follows it in this same file. **Dispatched 2026-08-10 with `RULE_BOUNDARY_HEIGHT`
stamped at 18,000** — see §*The boundary height, stamped*, which also carries the two riders
that stamping produced.

---

## Opening prompt (paste this to the builder session)

You are a builder session for `qumbra-labs/qumbra-lab`. Work in a fresh worktree:
`git worktree add ../qumbra-lab-i299rule -b claude/i299-emission-rule` and never touch the
main working tree or `qumbra-design`. Commit in stages (each stage below = at least one
commit; an unfinished uncommitted stage is lost work). Open a PR when done — **PR, never
merge**. All questions go as comments on lab issue #299 (or #303 for the math half); if you
are blocked and no reply has arrived, take the **smaller** action, mark it separable, and
say in the PR that you asked and proceeded. The full unfiltered workspace suite is the bar:
`scripts/rig run -- cargo test --release --workspace -- --test-threads=1` — rig-locked,
serial; reconcile your total against the 1360 baseline out loud. Enumerating breakage uses
`--no-fail-fast`; the acceptance run is the unmodified command. Read
`docs/prompts/i299-emission-rule-builder-prompt.md` (this file) §Task book before writing
any code, and read the two rulings it implements:
lab #303 `#issuecomment-5234169154` (the math-exact ruling) and
lab #299 `#issuecomment-5226686415` (the sequencing ruling).

**The boundary is stamped: `RULE_BOUNDARY_HEIGHT = 18_000`.** That is the last height mined
and validated under the f64 schedule; the exact schedule and the `body.coinbase` rule both
bind from 18,001. Build against a named constant, never the literal inline. It is a
grid-legal halt height (18,000 = 8 × 2,250, #74's H2 rule) that is deliberately not a
committee-epoch rotation, and at the live cadence it arrives around 2026-08-20 — read it as
a height, never as a date. §*The boundary height, stamped* carries two riders that change
what you build, including one that overrides a sentence of stage 2; read it before stage 1.

---

## Task book

### What this baton builds, in one paragraph

The canonical emission schedule becomes the **exact-decimal** evaluation (math-exact,
#303's ruling clause 1), and consensus finally **enforces** it:
`body.coinbase == coinbase(height)` for `height ≥ 1` (#299). Both arrive together at a
**halt-height boundary** (#74/#81 machinery); everything before the boundary is
grandfathered **as recorded** — the epoch-1 −4114 block, every glibc-vs-exact ±1, all of
it. Pre-boundary accounting **pins, never recomputes** (#303 clause 3). The
`SupplyLedger` reorg gap (#299 §4) closes in the same PR.

### The boundary height, stamped: `RULE_BOUNDARY_HEIGHT = 18_000`

Stamped at dispatch, 2026-08-10, by the coordinator under Larry's delegation. It is no
longer yours to choose and no longer a placeholder. Build everything against the named
constant — never the literal inline — and let the drill (stage 5) keep proving the
machinery at its own low test height.

Semantics, in the #74/#81 vocabulary the code already speaks: 18,000 is a **halt height**,
so `accepts_height(18_000)` is true, `accepts_height(18_001)` is false, `domain_at(18_000)`
is `None`, and `domain_at(18_001)` is the new domain. In this baton's words: **18,000 is the
last block under the f64 schedule, and 18,001 is the first block at which the exact schedule
and `body.coinbase == coinbase_exact(height)` bind.**

Why this height — stated so you can tell whether a later re-stamp is legal:

- **The grid rule (H2) constrains it.** `release.rs` refuses an off-grid halt height at
  startup: it must be a multiple of `CHECKPOINT_CADENCE_BLOCKS = 8`. 18,000 = 8 × 2,250.
  **Any re-stamp must also be ≡ 0 (mod 8)** — that is a structural refusal, not a taste.
- **It is not a committee rotation.** `EPOCH_LENGTH_BLOCKS = 1,152` is FROZEN, so epoch 15
  is `[17_280, 18_431]` and 18,000 sits 720 blocks inside it, ~9 h clear of the next
  rotation at 18,432. Landing a halt/resume on a roster rotation buys nothing and puts two
  transitions in one window.
- **Lead time, measured not guessed.** At the stamp the live T0 net was at tip **6,280**
  (2026-08-10 06:36 +08, `explorer.qumbra.org/v1/health.json`; epoch 5, `regime=final`,
  4 peers), and observed cadence is ~47.7 blocks/h against the FROZEN 75 s target. 18,000
  is therefore ~11,720 blocks ≈ **10 days** out (≈ 2026-08-20, ±~½ day of PoW variance).
  That is the slack for this PR, coordinator acceptance, the T-ops pin computation, the
  revision mint, the image, Larry's four-host roll, and the activation drill.
  **Overshooting costs a few more days of an unenforced schedule; undershooting halts
  finality on a live net with no resume binary in existence.** That asymmetry, not
  impatience, sets the number.

🔴 **Rider 1 — an epoch-aligned boundary is impossible. This is a finding, not an
oversight.** An epoch ends at `1152·N − 1`, which is always **odd**, while H2 demands a
multiple of 8. So no legal halt height can ever be an epoch end: **exactly one epoch
straddles the boundary no matter what height is stamped.** Here that epoch is 15. Do not
spend a round trip trying to make the straddle go away.

🔴 **Rider 2 — the straddling epoch's expected value is piecewise, and this overrides one
sentence of stage 2.** Stage 2 says straddling epochs "use `s_atomic_exact` endpoints".
Applied literally to epoch 15 that **recomputes** heights 17,280–18,000, which #303
clause 3 forbids ("pre-boundary accounting pins, never recomputes") — and against a
zero-bessel tolerance a single grandfathered ±1 in that prefix would raise a **false
DIVERGENT** on epoch 15: precisely the cry-wolf failure stage 4 exists to prevent. So for
the one straddling epoch: **expected = the pinned recorded value of the pre-boundary prefix
(17,280..=18,000) + the exact walk of the suffix (18,001..=18,431)**. Test-lock that shape
with a deliberate ±1 planted in the prefix and assert the epoch still reads zero bessel.
Epochs 0..=14 pin whole, scar included. If you think this rider is wrong, argue it on #303
before building around it.

One consequence worth naming: pinning now covers **15 epochs**, not the "~5–9 epochs"
#303's ruling estimated at activation. That is six more pinned literals and nothing else;
the ruling's clauses are unchanged.

**Re-stamping** is legal and cheap only until the new binary's image is built — the constant
compiles in. If this baton or the roll slips such that 18,000 comes within ~2 days of the
fleet being ready, ask on #299 for a fresh stamp instead of racing the height.

### Stage 1 — the exact schedule (`emission_exact`, no libm reachable from consensus)

- New module beside `emission.rs`: integer/fixed-point evaluation of
  `s_atomic_exact(h) = round_half_up(10⁸ · 50·(1−q^h)/d)`, `q = 9999991763/10¹⁰`,
  `d = 8237/10¹⁰`, both read as exact decimals. Square-and-multiply for `q^h` in wide
  fixed point (u128 limbs or a small bignum — your call, argued in the PR) with a proven
  error bound below half of the final rounding ulp; **ties decided in exact arithmetic**
  (they are decidable — the denominators are powers of ten; if you find a height where
  your bound cannot decide, STOP and post it on #303, do not guess).
- Tail: for `h ≥ h_t = 4,503,536`, `coinbase_exact(h) = 122,441,000` **exactly, as a
  constant** — test-locked, including the h_t crossing itself.
- **Golden locks (ruling clause 4), all three**: (a) the census artifact's exact-decimal
  reference stream (gist linked from #303; its 80/120-digit SHA-256
  `2e26f6ff674be57f5f997ce45bfa50b1ea9ad95351ad4f6c1d712a709d544a69`) — recompute the
  stream over the full `0..=4,600,001` range and match the hash (this is minutes of CPU,
  run it rig-locked, once, and pin the result as a slow `#[ignore]` test plus a fast
  sampled test for CI cadence); (b) the 12 measured cross-libm heights — the exact value
  must equal the census's exact answer, NOT either f64's; (c) a no-float guard: the module
  compiles under `#![deny(clippy::float_arithmetic)]` (or an equivalent structural test)
  so no libm can ever leak back in.

### Stage 2 — the boundary switch, and pins instead of recomputation

- `emission::coinbase(h)` grows boundary awareness at its callers' seam (shape yours,
  argued): **assembly and validation above the boundary use `coinbase_exact`;** the f64
  path survives ONLY as the pre-boundary historical schedule.
- **Committee accrual** (`recovery.rs`): the cumulative accrual at the boundary is pinned
  as a constant (computed once on a glibc host at activation — the task book notes the
  T-ops step; your code takes the constant); recomputation-from-genesis = pinned constant
  + exact walk above the boundary. No node ever re-evaluates the f64 schedule to agree
  with another node.
- **Supply attestation** (`supply.rs`): epochs whose end ≤ boundary keep their recorded
  expected values (pinned literals at activation, same T-ops note); epochs straddling or
  above use `s_atomic_exact` endpoints. The epoch-1 scar stays visible and gains its
  known-scar annotation (#299 ruling item 2) if the display layer is in reach; if that
  widens scope, flag it separable.
- The `#81` revision machinery carries the schedule rule: the post-boundary `Revision`
  names the exact schedule so `check_against_marker` refuses a pre-rule binary resuming
  past the boundary (the #81 domain discipline, applied to this rule).

### Stage 3 — the validity rule (#299)

- In `validate_body` beside `MissingCoinbasePayee`: for blocks **above the boundary** and
  `height ≥ 1`, `body.coinbase != coinbase_exact(height)` → a named `BodyError`. Genesis
  and all pre-boundary history are exempt **structurally** (the boundary check, not a
  special case list); the #299 verification comment's trap is test-locked: the rule never
  evaluates `coinbase(0)` against genesis's committed 0.
- Negatives per house standard: an over-paying and an under-paying block above the
  boundary both refused with the named error; the SAME bodies below the boundary accepted
  (grandfathering is a property, not prose); the k=1 adjacent-height substitution (the
  live 1377 shape) refused above the boundary.

### Stage 4 — `SupplyLedger` reorg reconciliation (#299 §4)

A reorg below `next_height` currently leaves the orphaned block's coinbase in the sum
forever. Fix shape yours (rewind hook from `rewind_to`, or rebuild-on-reorg), but the
test is fixed: orphan a block whose coinbase differs, reorg past it, the ledger's row
re-derives to the canonical chain — and a false DIVERGENT can no longer be produced by
the reorg path (with the rule active, DIVERGENT is a real alarm and must not cry wolf).

### Stage 5 — the drill

Extend the halt-height drill family: a two-binary handoff at a test boundary where the
old binary mines an f64-schedule block below and the new binary refuses exactly the same
committed value above. This is the #74 drill discipline applied to the first *real*
scheduled rule change.

### Stop points (stop and report on #299, never proceed)

The genesis hash moving; any wire codepoint or payload change; any FROZEN v1.0 constant;
anything in `qumbra-deploy`; the census stream hash not reproducing (that is a finding
bigger than this baton); a tie your error bound cannot decide.

### Acceptance (what the coordinator will run)

Full unfiltered workspace suite, serial, rig-locked, reconciled against 1360 (name both
numbers); the census-hash golden reproduced independently; diff read for boundary
structure (no special-case lists), negative-test reality (rules that fire), and the
no-float guard. The live half — boundary stamp, fleet roll, activation drill — is
T-ops's and Larry's, after merge.
