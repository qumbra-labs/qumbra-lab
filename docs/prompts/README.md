# Builder prompts — the instruction a baton actually received

The **task-book** lives in the issue and is versioned by GitHub. The **prompt** is what a builder session is actually handed, and until 2026-07-26 it lived untracked in the workspace root. That was the wrong asymmetry: the less authoritative artifact was version-controlled and the more operative one was not.

Every prompt here is dispatched by pasting its contents into a fresh builder session. They are kept — including superseded and withdrawn ones — because how a baton was briefed is part of how its result should be read.

## Why the history matters, with today's example

`i77-builder-prompt.md` went through four revisions on 2026-07-26:

1. initial;
2. **+4 corrections** after a pre-dispatch review — the candidate-B shape conflicted with the "check first" rule, a whole seam (disk-log replay) was missing, a seam count disagreed with itself, and P4 was over-broad for a header-only mining lane. Dispatching v1 would have wasted a baton;
3. heading count removed (it contradicted a rule the same prompt was imposing) and a design observation pulled forward from the addendum;
4. the `operating-model` §3.3 GitHub-as-bus clause, which became mandatory that afternoon.

None of that was recoverable from anywhere but a chat transcript. Now each revision is a commit with a reason.

**Reviewing a prompt against `main` before dispatch is standard here, not optional** — see the withdrawn `#24` task-book (`../issue24-taskbook-conflict.md`) for what skipping it costs.

## Contents

| file | baton | state |
|---|---|---|
| `t05-builder-prompt.md` | M10-T0-5 cross-node vote aggregation (#70) | merged, PR #72 |
| `i24-builder-prompt.md` | #24 merge-binding | **withdrawn** — its task-book was written from a stale issue body; path 1 had shipped four days earlier |
| `d3-builder-prompt.md` | #24 D3 leaf F0 digest binding | **merged, PR #82** — closed the last item of #24 |
| `halt-height-builder-prompt.md` | #74 halt-height mechanism | **merged, PR #76** |
| `i77-builder-prompt.md` | #77 header↔body binding | **merged, PR #79** |
| `m11-discovery-builder-prompt.md` | [#83](https://github.com/lai3d/qumbra-lab/issues/83) M11 peer discovery | **merged, PR #86** — the first M11 baton |
| `i87-builder-prompt.md` | [#87](https://github.com/lai3d/qumbra-lab/issues/87) committee round diagnostics + structured metrics | **ready to dispatch** — the long pole: it gates the `DEGRADED_MODE_LAG_BLOCKS` question *and* rides the single redeploy that unblocks the four B-WAN drills |
| `i91-builder-prompt.md` | [#91](https://github.com/lai3d/qumbra-lab/issues/91) M11 peer hardening | **ready to dispatch** — independent of #87 in content, but competes with it for the rig; ships in the same redeploy |
| `halt-height-taskbook-DRAFT.md` | #74 | **superseded** by the issue #74 task-book. Kept deliberately: its §1 H3 is the version the coordinator later **rejected as contradicting `committee-and-governance` §4**, and a draft that was overruled is worth more on the record than one quietly deleted |
