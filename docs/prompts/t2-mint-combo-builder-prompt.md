# T2 mint combo builder prompt — C1 + C2 + C3 + C4, one tree, staged (lab #470)

You are a CLI builder session for `qumbra-lab`. This is a **mint-class consensus baton** —
the heaviest class this repo has. Read, in order, before any code: the repo's `CLAUDE.md`
(acceptance = CI lane, `verify-graviton` label; staged commits are survival), lab issue
**#470** (the tracker — Larry's trigger-pull ruling and the binding structural requirement),
`docs/prompts/mint-combo-builder-prompt.md` (the 2026-08-04 mint's book — your discipline
template: stage boundaries, stop-points, byte-exact reproduction), and the two ruling
sources: `qumbra-design/pool-payout-axis-brief.md` (C1's (c) ruling) and
`qumbra-design/pool-t1-brief.md` §3 (C2's header ruling).

Worktree `../qumbra-lab-t2mint`, branch `claude/t2-mint-combo`. **Commit per stage. Open ONE
PR after stage 0 and keep pushing stages to it — the coordinator reviews at every stage
boundary. NEVER merge.** Report each stage completion AND every stop-point on issue #470.

## 🔴 The one law above all others: `main` stays T1-operable

T1 is a live public net; strangers build `main` from the public join docs; the fleet's next
image builds from it. Every T2 format lands **keyed off the genesis file's format version**
(T1 = v4; T2 = v5). **The compat lock is byte-identity of every existing T1 golden**: the
T1 genesis hash `138e1524…addb`, the v2 AND v3 body-commitment goldens, the serving vector,
`CONSENSUS_WIRE_BYTES = 148,625`, the frozen digest `a54e73ce…`. If any stage cannot
proceed without moving one of those, that is a STOP — report on #470 and wait.

## The cargo, per stage

### Stage 0 — the plan, the keying design, and the survey (no consensus code)

1. Map how the genesis format version currently reaches (or fails to reach) the header
   codec, body codec, and rule schedule. Design the v5 keying: ONE selection point at
   genesis load fanning out to header-form, body-form, coinbase-form, and rule-schedule
   choices — not per-call-site version sniffing. Name every seam you will touch.
2. **C3 sweep**: re-verify #232 / #233 / #234 against today's `main` (bodies may have
   drifted), and sweep for accumulated same-class items filed since. Propose the exact
   batch. **C3 items apply to the v5 forms only** where they change committed bytes — the
   v4 forms are frozen history.
3. **Rule-schedule design for T2**: on a v5 genesis, exact emission AND the name-service
   rule are native from height 0 — no boundary, no pins, no `KNOWN_SCAR`. The T1 boundary
   machinery stays, keyed to v4 genesis. State how the schedule selection composes with
   the #74/#81 halt-marker machinery (T2 must still be ABLE to halt-upgrade later).
4. Deliverable: the stage plan as your PR's opening body + a stage-0 commit with any pure
   plumbing (version plumbing that changes no behavior on v4). **Coordinator reviews
   before stage 1 begins.**

### Stage 1 — C2: the v5 header layout

Per the pool-t1-brief §3 ruling verbatim: nonce becomes u64 at preimage offset 39–46
(low 4 bytes miner-ground, high 4 pool extra-nonce); bytes 32–38 = 1-byte header format
version + u48 height. v4 headers byte-identical (golden-locked). PoW continuity: the rx/0
identity is proven in-tree (#356's official-vector test) — what changes is the preimage
LAYOUT, so lock a v5 header golden + a v5 PoW-input vector, and show LWMA/difficulty
machinery is layout-agnostic. Adversarial: a v4 header presented to a v5 net (and vice
versa) is refused by name, never misparsed.

### Stage 2 — C1: the payee-list coinbase (option (c))

Versioned multi-recipient coinbase structure per the payout-axis ruling: **N=1 at birth**
(the cap is a rule-change lever, not a launch feature), sum-of-payees must equal the exact
schedule's coinbase — the validation seam is the same one the emission rule owns; extend
it, do not fork it. The single-payee v5 block's semantics must be provably equivalent to
today's single-rkm payout (the wallet/miner_rkm path keeps working unchanged on T2).
Negative tests: sum mismatch refused; N>cap refused; zero-payee refused.

### Stage 3 — C3 + C4 fold-in

The approved C3 batch lands in the v5 forms (arity counts into the v5 body commitment
per #232; single `logical_actions` encoding per #233; the #234 constant corrected at its
binding copy — that one is v4-safe, verify and say so). C4: confirm the v5 rule schedule
from stage 0 makes names + exact emission native from 0, with the drill seams
(`*_above` forms) still exercising both eras.

### Stage 4 — the T2 genesis mint + goldens + fit-checks

Genesis format v5 minted through the real CLI: **reproduce the genesis hash byte-identical
twice** (the mint discipline; the coordinator reproduces independently at acceptance).
New goldens: v5 header, v5 body commitment, v5 wire size (state it — C3's arity counts may
move it a few bytes from 148,625; that is EXPECTED and it is a NEW number beside the old,
never an edit of the old), fit-checks re-run. The frozen STARK consensus config
(b16/q21/g22/fp16/a16) must be UNTOUCHED — nothing in this cargo reaches the circuit;
assert the frozen digest is unchanged.

## Stop-points (each = report on #470 and WAIT; the mint precedent is three mid-flight
task-book corrections, all caught at stage boundaries — that machinery is wanted here)

- Any T1 golden moves, or `main` stops building a T1-operable binary at any commit.
- Anything reaches the circuit, a FROZEN v1.0 constant, role codes, or the perm budget.
- The keying design wants per-call-site version sniffing instead of one selection point.
- A C3 item turns out to bind v4 bytes.
- Anything in `qumbra-deploy` or the live fleet — the T2 LAUNCH is a separate later
  decision; this baton delivers a mintable tree, nothing deployed.

## Acceptance (per stage at the boundary; final at stage 4)

- CI green per stage push (`verify-graviton`), arithmetic reconciled out loud against the
  baseline at your branch point (state it) — plus the negatives (`FAILED`/`panicked
  at`/`^error` zero).
- Stage 4: both genesis reproductions' hashes in the PR; the full old-vs-new golden table;
  the honest remainder (what T2 launch still owes: T-ops ceremony, migration narrative,
  fee-table re-ratification at the launch stamp — none of it yours).
- The fee table and every §2-numbers question: **the merge is NOT the stamp this time** —
  C6's re-ratification happens at LAUNCH, so carry the current values and mark them
  `pending launch re-ratification`.
