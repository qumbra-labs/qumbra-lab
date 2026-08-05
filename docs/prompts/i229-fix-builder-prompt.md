# Task book — #229: the stranding fix, stage-0-gated on the mechanism

**For a CLI builder session, deliberately not Multica** — the fix is consensus-adjacent node
code and the Multica workspace context is required to refuse it. Branch `claude/i229-fix` off
current `main`; staged commits; **open a PR and never merge it** (coordinator merges after
acceptance). Estimates in Claude session-hours: stage 0 ≈ 1–2 sh, stage 1 ≈ 2–4 sh.

**The one rule this book exists to enforce: no fix code before the mechanism statement is
ratified.** The ordering question ("is the ask a symptom of the freeze or its cause") is an
unsettled premise, and this repo has paid twice for building on one of those (#24; the mint
book's stage 1). Stage 0 ends at a hard STOP.

## Stage 0 — the ordering read + the mechanism statement (~1–2 sh)

### Ground truth you must reconcile against (all on [#229](https://github.com/qumbra-labs/qumbra-lab/issues/229) — read the whole thread)

- **Onset signature, 2/2 at 30 s grain** (T-ops container-log brackets): in one tick,
  `schain` flips `main→fork` AND `breq` goes `0→1` AND `bask` points at a fork point
  **below the node's own `stip`** (`bask=1@556` against `stip=558`; `bask=1@571` against
  `stip=573`). `tip`/`stip`/`slag` do not move at onset — the node was **fully caught up**
  (`slag=0`) when it happened.
- **The difference between the two onsets**: node2's `stipid` was **swapped at the same
  height** (573 kept, identity changed); node3's was not. Two entry paths into one stranded
  state, or one path with two appearances — say which, from code.
- **Instance 4's onset (07:08:48) precedes finality's last advance (07:09:38) by 50 s.**
- **Recovery, 4/4**: `breq→0` and the `stip` unfreeze are coincident (bracketed to 61 s on
  instance 4). Strandings run 1 h 25 m – 2 h 09 m with a fast (~15–20 min) catch-up.
- **Served-not-applied is confirmed** (this issue's title finding): 12/12 peers served,
  2,195 asks, `bdrop=0`, and the node does not apply — the gate is missing.
- **Onsets are locally unobservable**: the rig's minute watches carry suspension holes
  (14/16/16/5/41 min) — container logs and code are the only instruments. Four-host
  ±5-minute windows around both onsets are being attached by T-ops; reconcile against them.

### The questions, in order

1. **Code order**: where does the outstanding-ask count that surfaces as `breq=`
   increment (`qlab-p2p/src/adapter.rs:935–1027`, `observe_state_stall` /
   `outstanding_breqs`; emission at `qumbra-node/src/run.rs:1264–1296`), relative to where
   applying stops? Which of the two five-minute-grain onset orderings (freeze-then-ask,
   ask-then-freeze) are possible in code, and does the 30 s same-tick signature
   discriminate further?
2. **What flips `schain`**: `schain=fork` means the applied tip is no longer the main-chain
   block at its height (`qlab-node/src/telemetry.rs:279–391`) — i.e. **fork choice moved off
   the node's applied chain**. What event arrives to cause that on a `slag=0` node — a
   competing header set, a checkpoint, something else? The four-host windows say what was
   in flight; the code says what reacts to it.
3. **The fork point in `bask`**: `bask=` carries the ask set's size and **the fork point**
   (`qlab-p2p/src/bodywait.rs:334`). Both onsets ask at the fork point below their own
   stip. Trace what the node intends to do with those bodies and where that intention dies —
   the missing gate, named to file:line.
4. **The stipid swap**: what code path replaces the applied-tip identity at an unchanged
   height (node2) and which skips it (node3)?
5. **Reconcile with the #104/#130 family**: #130 (a) (PR #142) taught the state machine to
   catch up ascending for headers it holds. State exactly why that path does not fire here.

### Stage-0 deliverable, then STOP

A **mechanism statement** on #229: what starts a stranding, what sustains it for ~2 h, what
ends it — every claim either code-cited or observation-cited, every unknown named as such.
If the statement and any observation disagree, say so rather than smoothing it. **Do not
write fix code. The coordinator ratifies the statement (or bounces it) on the issue.**

## Stage 1 — the fix, per the ratified mechanism (~2–4 sh)

Written after ratification; the shape below is a guardrail, not a prescription.

- The fix is expected to live at the **apply gate for served bodies** and/or the event
  handler stage 0 identifies — node-side only. **If the ratified mechanism implies any wire
  or payload change, STOP and report**: that changes the deployment story (rolling roll vs
  re-mint) and is not this baton's call.
- Tests owed, minimum: the **healthy-recovery baseline** (the 4/4 `breq→0` ⟺ unfreeze
  coincidence must survive the fix); an in-process reproduction of the onset signature if
  the mechanism permits one (same-tick `schain` flip + ask-below-stip), refused-then-fixed
  in both mutation directions (#106 discipline); regression cover for whichever of
  #104/#130's assertions the fix touches.
- The bar, unchanged: `scripts/rig run -- cargo test --release --workspace -- --test-threads=1`,
  arithmetic reconciled out loud, negatives verified. Enumerate with `--no-fail-fast` first
  if the blast radius is wide (CLAUDE.md two-phase rule).

## Standing rules

- Rig discipline per `docs/the-rig.md`; every heavy run through the wrapper.
- Ask on the issue when blocked; if no answer by the time you are blocked, take the smaller
  action, mark it separable, and say so in the PR.
- Report what you did NOT verify, most-likely-to-break first.
