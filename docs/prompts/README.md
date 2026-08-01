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
| `m11-discovery-builder-prompt.md` | [#83](https://github.com/qumbra-labs/qumbra-lab/issues/83) M11 peer discovery | **merged, PR #86** — the first M11 baton |
| `i87-builder-prompt.md` | [#87](https://github.com/qumbra-labs/qumbra-lab/issues/87) committee round diagnostics + structured metrics | **ready to dispatch** — the long pole: it gates the `DEGRADED_MODE_LAG_BLOCKS` question *and* rides the single redeploy that unblocks the four B-WAN drills |
| `i91-builder-prompt.md` | [#91](https://github.com/qumbra-labs/qumbra-lab/issues/91) M11 peer hardening | **ready to dispatch** — independent of #87 in content, but competes with it for the rig; ships in the same redeploy |
| `i101-builder-prompt.md` | [#101](https://github.com/qumbra-labs/qumbra-lab/issues/101) a mined coin can be spent | **merged, PR #113** — carried three STOP-POINT rulings as preconditions, and said which of them was most likely wrong |
| `i84-builder-prompt.md` | [#84](https://github.com/qumbra-labs/qumbra-lab/issues/84) finalized-checkpoint identity | **merged, PR #110** — scope was roughly half the issue; #87 had already closed most of item (2) |
| `i130a-builder-prompt.md` | [#130](https://github.com/qumbra-labs/qumbra-lab/issues/130) **part (a) only** — the state machine desynchronises from its own chain | **ready to dispatch** — the sole remaining precondition for the four §4 drills (`qumbra-deploy` OPERATOR §4). (b) and (c) are explicitly out of scope; (b) needs a trust-model ratification that is Larry's |
| `i102-builder-prompt.md` | [#102](https://github.com/qumbra-labs/qumbra-lab/issues/102) coinbase maturity is policy, not structure | **ready to dispatch** — must land **before** the genesis mint: option (b) changes every root from height 1, so landing it after means a second mint |
| `i106-builder-prompt.md` | [#106](https://github.com/qumbra-labs/qumbra-lab/issues/106) **item (1) only** — a node on an empty data dir mines instead of syncing | **ready to dispatch** — the last precondition before the mint. The issue bundles three findings and the prompt's first job is to stop the baton fixing all three; #130 (a) explicitly does **not** cover this |
| `i143-builder-prompt.md` | [#143](https://github.com/qumbra-labs/qumbra-lab/issues/143) what binds the first permutation's input state | **ready to dispatch** — read-only; the one thing #78's audit named and refused to bless, and the only one of its questions inside the **FROZEN consensus AIR**. Carries the audit's methodology finding, because the obvious instrument returns a false negative for exactly this column |
| `i115-builder-prompt.md` | [#115](https://github.com/qumbra-labs/qumbra-lab/issues/115) genesis binds its own body | **ready to dispatch** — the only item on the mint's critical path with nobody on it. Its golden vectors **must** break, which is the exact opposite of `i78`-era decoder work, and the prompt leads with that because getting it backwards looks like success either way |
| `halt-height-taskbook-DRAFT.md` | #74 | **superseded** by the issue #74 task-book. Kept deliberately: its §1 H3 is the version the coordinator later **rejected as contradicting `committee-and-governance` §4**, and a draft that was overruled is worth more on the record than one quietly deleted |

## Two prompts, one rig — read this before dispatching both at once

`i130a` and `i102` are independent in content and **compete for the machine**. A release workspace suite peaks near 16–30 GB on a 36 GiB box, so two of them running acceptance at the same time kills both. Each prompt points its builder at [issue #64's](https://github.com/qumbra-labs/qumbra-lab/issues/64) pinned comment for rig status and requires it to report whether it waited.

They are also **not interchangeable in urgency**, and the reason is different in each case:

- **`i130a` gates the drills.** Every §4 criterion is *"did the two halves finalize the same thing"*, and (a) is the only piece that makes the state-machine lag visible — without it a drill still reports on the view that works.
- **`i102` gates the mint.** Option (b) moves the coinbase leaf from `h` to `h + 144`, which changes every commitment root from height 1 onward. That is a hard consensus fork, so it must land before the new net starts or it costs a second mint.
