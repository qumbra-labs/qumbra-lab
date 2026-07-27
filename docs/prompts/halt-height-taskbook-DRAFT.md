# DRAFT task-book — halt-height upgrade mechanism + drill (M11 open, pulled forward)

**Status: DRAFT, awaiting Larry's nod before it becomes a lab issue.** It is drafted rather than
filed because it builds the *only sanctioned path by which a FROZEN v1.0 constant can ever change*,
and that is a directional call, not a routine baton.

Coordinator: `qumbra-coordinator-opus-5`, 2026-07-26.

---

## 0. Why this is worth pulling forward from M11

Larry's standing rule: **the FROZEN v1.0 set changes only via halt-height + a revision document.**
Today that path exists **only as a comment**. Two occurrences, both prose:

- `crates/qlab-consensus/src/lib.rs:132` — "halt-height upgrade carrying its own revision doc"
- `crates/qumbra-node/src/genesis.rs:57` — "halt-height upgrade carrying its own revision doc, never silently"

There is no mechanism. So the governing rule of the whole frozen parameter set is, in
implementation terms, an unimplemented promise. `testnet-plan.md` lists the drill under M11 as
"practice the muscle before it matters" — the muscle does not exist yet.

It is also **fully VPS-independent**: the 4-node docker net rehearses it end to end.

## 1. What must be decided before code (coordinator stamps — draft, for Larry's review)

These are the design questions. My proposed answers are stated so Larry can push back on the
*decisions*, not just the schedule.

**H1 — where the halt height lives.** Proposed: **baked into the binary as a release constant**,
not in config and not in genesis. Grounds: a config-supplied halt height means one mis-edited TOML
forks a node off; genesis cannot carry a height chosen years later. "This release stops at H" is a
property of the release, and it makes the upgrade a *binary* swap, which is what an operator can
actually be drilled on. Config may **override downward** for testing only, behind a loud opt-in
flag, never upward.

**H2 — what "halt" means, exactly.** Proposed: the node **applies block H and then stops** —
stops mining, stops accepting any block above H, stops signing checkpoints above H, and keeps
serving RPC/telemetry with a distinct `regime=Halted`. It does **not** exit the process: an
operator must be able to inspect a halted node. Rationale: halting *after* H makes H a clean
shared tip that both the old and new binary agree on, which is the whole point — the upgrade
boundary must be a state both sides can name.

**H3 — the anti-split-brain property, which is what the drill must actually prove.** An
un-upgraded node MUST NOT follow the post-halt chain, and an upgraded node MUST NOT accept
post-H blocks built under pre-halt rules. If both binaries can keep going on different rules, the
mechanism has failed at its only job. This is the test that matters more than the happy path.

**H4 — the revision document is part of the mechanism, not paperwork around it.** Proposed: the
binary refuses to resume past its halt height unless it carries a **revision identifier** (a
constant naming the revision doc and the parameter deltas), and it logs that identifier loudly at
startup. Grounds: Larry's rule pairs halt-height *with* a revision doc; if the code can resume
without one, the pairing is honored only by discipline. Cheap to implement, and it makes an
undocumented parameter change impossible-by-construction rather than forbidden-by-policy.

**H5 — nothing in this baton changes a FROZEN v1.0 value.** The drill exercises the *mechanism*
using a deliberately inert change — ideally a testnet-tunable parameter, or a no-op revision that
changes only the revision identifier. Building the road is not permission to drive on it.

## 2. Scope

1. Halt-height mechanism per H1–H4, in the consensus/node layer, with `regime=Halted` surfaced in
   telemetry alongside the existing `Final`/`Degraded`.
2. Resume path: the upgraded binary opens the persisted chain at tip H and continues, without a
   re-sync from genesis and without re-mining H.
3. The revision-identifier gate (H4) and its startup log line.
4. **The drill, on the docker net**, scripted as a `soak.sh` subcommand so it is repeatable:
   4 nodes run to a near halt height → all four halt at H with an identical tip → binaries are
   swapped → net resumes and finalizes past H.
5. **The negative drills** — these are the acceptance, not an extra:
   (a) one node left un-upgraded stays halted and does **not** follow the new chain;
   (b) an upgraded node offered a post-H block built under the old rules rejects it;
   (c) a binary with a halt height but no revision identifier refuses to resume.
6. A run doc in `docs/`, format per `docs/m10-t05-votes-run.md`, plus the operator procedure in
   the runbook — an operator should be able to execute the drill from the doc alone.

## 3. Stop-points

- If the mechanism appears to require changing any FROZEN v1.0 value to *build* it — stop.
- If, in drill 5(a), the un-upgraded node follows the post-halt chain, or the two binaries produce
  divergent finalized checkpoints at any height — **stop immediately and preserve state**. That is
  the failure this whole mechanism exists to prevent.
- If the resume path needs a re-sync from genesis, stop and report before working around it: that
  would make a real upgrade an outage rather than a pause.

## 4. Acceptance

Full unfiltered `cargo test --release --workspace` against the then-current baseline (569 as of
2026-07-26), the three negative drills each named and passing, the docker drill reproducible from
the run doc by someone who did not write it, and `regime=Halted` visible in telemetry throughout
the halt. No FROZEN v1.0 constant moved.

## 5. Estimated size

~4–7 Claude session-hours, plus docker wall-clock for the drill runs (the net must reach the halt
height; use a low halt height so this is minutes, not hours). Larry-side: nothing manual.
