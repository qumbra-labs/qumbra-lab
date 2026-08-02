# Where the CI suite runs, and what it costs

**Status: one half decided, one half open.** *(Amended 2026-08-02: option F added at Larry's
suggestion — EC2 on-demand under a Savings Plan — which the first version omitted, and which
displaces spot as the AWS option worth pricing. The amendment also surfaced that the T0 fleet's own
on-demand cost has never been measured.)* The architecture is settled and stays settled. The
*hosting* was never decided — it was assumed by a $2 experiment that has since become a $9.31
month — and the budget is Larry's call under R3. This file exists because that assumption had no
written record, which was discovered on 2026-08-02 when the budget page was read for the first
time.

中文: [`ci-runner-cost-decision-zh.md`](./ci-runner-cost-decision-zh.md) — EN is authoritative on
technical detail.

---

## 1. What is actually running today

`.github/workflows/suite-arm64.yml` runs `cargo test --release --workspace -- --test-threads=1`
on a **GitHub-hosted arm64 larger runner** (`qumbra-arm64-8`), triggered on `pull_request` when
`crates/**`, `Cargo.toml` or `Cargo.lock` change, plus `workflow_dispatch`.

Its own header still says, correctly, that **it is not the acceptance bar** — `CLAUDE.md` §5's rig
run is. That has not changed and nothing in this document changes it.

## 2. What was decided, and it is not in question

**arm64, not x64** (`PR #186`). The rig is an M3, the four T0 hosts are AWS `t4g.small` Graviton,
and the GHCR image is built for arm64. `randomx-rs` compiles a C++ library at build time and
aarch64 was a real problem there once — `M10-T0-3 Phase B-lite` records *"RandomX-on-Linux-aarch64
build RESOLVED"*. **A green on x64 would validate an architecture this project has never deployed
and never will.**

This is settled regardless of where the runner lives. Any hosting option below that cannot give
arm64 is disqualified before cost enters the argument.

## 3. What was never decided

**Nobody compared GitHub larger runners against EC2 spot, or against any other host.**

`PR #186` proposed *one manual run* to answer four questions, with the cost question phrased as
*"(3) × the per-minute rate"* and the stakes stated as *"if it does not, this file is deleted and
we have paid ~$2 to know."* At $2, a hosting comparison would have cost more than the experiment.
That was the right call then. The record simply never got revisited when the workflow moved from
`workflow_dispatch` only (`#186`) to firing on every PR push (`#191`).

**So "GitHub larger runner" is not a decision this project made. It is a default it inherited from
an experiment that succeeded.**

## 4. The numbers, and how they were obtained

Derived on 2026-08-02 08:53 +0800 from the org billing page and `gh run list`. **The billing page
gives one number — `$9.31 spent` of a `$20.00` budget with `Stop usage: Yes`.** Everything else
below is derived from it by division, and is labelled as such.

| | value | how |
|---|---|---|
| suite runs, 2026-08-01 | **19** | `gh run list --workflow=suite-arm64.yml` |
| suite minutes, 2026-08-01 | **671** | sum of `updatedAt − createdAt` |
| mean suite run | **35.3 min** | 671 / 19 |
| prefilter/check runs in the same window | 44 | `gh run list --workflow=prefilter.yml` |
| **spend, month to date** | **$9.31** | billing page, measured |
| **implied rate** | **≈ $0.0139/min** | 9.31 / 671 — an **upper bound** on the suite rate, because the 44 prefilter runs are inside the $9.31 and outside the 671 |
| **implied cost per suite run** | **≈ $0.49** | rate × 35.3 |
| remaining before hard stop | **$10.69** | 20 − 9.31 |
| **suite runs remaining** | **≈ 22** | 10.69 / 0.49 |

**This corrects an earlier estimate.** `PR #191` recorded *"~$0.7/run against a $20/month cap"*.
The measured figure is **$0.49**, about 30 % lower. The $0.7 was a pre-measurement estimate and
the arithmetic above is the first time actual spend was divided by actual minutes.

### The part that matters

**All 19 runs were on 2026-08-01.** The month has 29 days left and roughly 22 suite runs of
budget. At the observed rate the budget hard-stops within about one more working day, and
`Stop usage: Yes` means CI stops — it does not overspend and bill.

## 5. Where the money goes, which is not where it looks

Runs on 2026-08-01, by trigger:

```
4  workflow_dispatch  main
3  pull_request  claude/i133-d3-tombstone-restart
3  pull_request  claude/i130b-body-refusal-counter
2  pull_request  claude/i198-possession
2  pull_request  claude/i188-serve-committed-discovery
2  pull_request  claude/i180-sigkill-replay
1  pull_request  claude/i204-ask-what-is-finalized
1  pull_request  claude/i200-state-tip-mine-on-exhaustion
1  pull_request  claude/i187-fid-split-expression
```

🔴 **Several PRs ran the suite two or three times, and the coordinator reads exactly one of them.**

The verification procedure is *same-tree comparison*: the coordinator merges `main` into the PR,
pushes that merged tree, and compares the CI number against the rig number **on that tree**. A run
triggered by a builder's intermediate push is a number on a tree nobody will merge. It is never
read, never quoted in an acceptance comment, and never entered into the agreement ledger.

**Roughly half of the spend buys numbers nobody looks at.**

`cancel-in-progress: true` (`PR #191`) already truncates the superseded run when a newer commit
lands, which is why three runs show as `cancelled` — but a cancelled run has still burned the
minutes it ran, and the three cancellations together cost about 81 minutes.

## 6. What CI is actually for, stated plainly before anything is cut

**It is not speed, and it is not a second opinion on correctness. It is R1.**

> *The session that produces evidence must not be the session that rules on it.*

Today the coordinator runs the suite on its own rig and then rules on the result. CI running the
same tree independently is the only thing in the current setup that makes evidence independence
**structural** rather than a matter of the coordinator's discipline. `PR #186` said this outright
as the reason to consider making CI the bar.

There is a second, smaller value: the runner is **Linux/arm64** and the rig is **macOS/arm64**. For
a codebase whose defects this month have been in persistence, sockets and process restart, a second
operating system is not a rounding error.

### The honest ledger

**Seven same-tree comparisons. Seven agreements. Zero disagreements.**

(1030, 1031, 1045, 1046, 1051, 1056, 1060 — and since: 1074 on `PR #202`.)

**The procedure has not yet caught a defect.** It is cheap insurance whose premium is now visible,
and that fact belongs on the table when deciding what to spend. `PR #191` pre-registered what a
disagreement would mean — *"that divergence is worth more than the whole experiment"* — and it has
not happened.

## 7. The options

Assessed against: arm64 (mandatory, §2), R1 independence (§6), cost, and what it costs *to run*.

### A. Keep the GitHub larger runner, raise the budget

Changes nothing structurally. **R3: spend needs Larry, explicitly, every time.** The coordinator
does not raise this and has not.

At the measured $0.49/run, a month of the current *procedure* — not the current *rate* — is about
one merged PR's worth of runs each. The rate problem is §5, not the hosting.

### B. Keep the runner, fix the trigger — free, reversible, one file

Trigger the suite only on the tree the coordinator will actually read. Options within this: a
label the coordinator adds when pushing the merged tree, a `merge_group`, or restricting
`pull_request` to `synchronize` events from the coordinator's push only.

**Cuts spend by roughly half and loses no information that is currently used**, because the
information currently used is one run per PR — the merged-tree run — and this keeps exactly that.

**This does not need a budget decision and does not need Larry.** It is a single-file, reversible
change to `suite-arm64.yml`, and a docs-only or workflow-only PR does not trigger the suite (the
`paths` filter from `PR #191`), so proposing it is itself free.

**Implemented 2026-08-02:** `pull_request: types: [labeled]`, plus a job-level `if` checking the
label is `verify` (the `labeled` event fires for *any* label, so without the name check an
unrelated label would spend 34 paid minutes). `workflow_dispatch` bypasses the gate deliberately —
the manual path is already an explicit act.

🔴 **The ordering this creates, and it is a trap of exactly the shape this project keeps paying
for: push the merged tree FIRST, then apply the label.** Labelling before the push runs the suite
against the pre-merge head and returns a number that *looks* like a same-tree result and is not.
The count would still reconcile against the PR's own base, so nothing would flag it. Re-applying
the label re-runs on the current head, and `cancel-in-progress` kills the stale run.

### C. AWS EC2 Graviton spot, self-hosted runner

Cheapest per minute by a wide margin — a `t4g`/`c7g`-class spot instance is on the order of
one-fifth to one-tenth the per-minute cost, and this project already runs Graviton hosts and
already has Terraform (`qumbra-deploy/terraform/`). **The arm64 requirement is satisfied natively.**

What it costs that the table does not show:

- **A machine to maintain**, and a runner registration to keep alive. The four T0 hosts are already
  an operational surface; this adds a fifth that is not part of the net.
- **Spot interruption in the middle of a 35-minute serial suite.** A 2-minute eviction notice
  against a run that cannot be resumed means the run is lost and re-run, and the re-run is also
  interruptible. The suite's `--test-threads=1` is not negotiable (`CLAUDE.md` §5), so it cannot
  be shortened by parallelism.
- **It weakens the one thing CI is for.** A self-hosted runner the coordinator provisions,
  configures and can reach is closer to the rig than a GitHub-hosted one is. R1's independence is
  partly *organisational* — a runner nobody in this session can touch mid-run is a stronger
  witness than one this session administers.
- **Self-hosted runners executing pull-request code have a known security shape.** It is muted here
  — private repo, one human, agent-authored branches — but "muted" is not "absent", and it should
  be written down rather than discovered.

**None of this disqualifies C.** It says C's real price is operational and structural, not
per-minute, and that a comparison run purely on the per-minute rate would be misleading.

**Superseded in part by F below**: if the argument for leaving GitHub is cost, on-demand with
start/stop captures most of the saving without the eviction failure mode, so **C is now the weaker
of the two AWS options** and is kept here only because the per-minute figure is genuinely lower.

### F. AWS EC2 Graviton **on-demand**, started and stopped around each run — optionally under a Savings Plan

**Raised by Larry, 2026-08-02, after this document's first version omitted it.** It is not a variant
of C; it removes C's one *technical* objection outright.

**Spot's eviction is fatal here and on-demand's is not.** A two-minute eviction notice against a
35-minute serial run that cannot be resumed means the run is lost, and the re-run is equally
interruptible. `--test-threads=1` is not negotiable (`CLAUDE.md` §5), so the run cannot be shortened
by parallelism to duck under the risk. On-demand simply does not have this failure mode.

**The instance must be stopped when idle, and that is the whole cost model.** EC2 bills by the
second while running. The suite runs on the order of one hour a day; a machine left up would bill
720 hours a month to do 30 hours of work. So option F is really *on-demand plus start/stop
orchestration*, and the orchestration is the thing being bought, not the instance.

**Where a Savings Plan does and does not help — and this is the part worth getting right.** A
Compute Savings Plan commits to a fixed **dollars-per-hour, continuously**, for one or three years,
in exchange for a discount. **That instrument is a poor fit for a workload used ~4 % of the time**:
sized to cover the CI burst it pays for ~23 idle hours a day, and sized small enough not to, it
discounts only a sliver. **A Savings Plan bought *for CI alone* would likely cost more than it
saves.**

**But this project already runs a continuous on-demand fleet, and nobody has priced it.** The four
T0 hosts are `t4g.small`, on-demand, in four regions (`us-east-1`, `eu-west-1`, `ap-southeast-1`,
`ap-northeast-1`), and `terraform/` contains **no `spot` or `market_options` block anywhere** — so
all four are full on-demand. They have been up continuously since 2026-07-26 15:43: **≈161 hours
each, ≈646 instance-hours, and still running.**

🔴 **That fleet is the workload a Savings Plan actually fits, and it is almost certainly a larger
line item than the entire CI question this document was opened about.** Four small instances
running 24/7 across four regions is on the order of a few tens of dollars a month at list price
against a **$20** CI budget — and a Compute Savings Plan applies **across instance families and
regions**, so one commitment sized to the T0 fleet would also absorb a CI instance's occasional
hours as a side effect.

**Caliper on those dollar figures: none of them are measured.** This document's §4 numbers come
from GitHub's billing page divided by run durations. **The AWS side has not been read at all** —
no Cost Explorer figure, no bill, no per-region price lookup. The instance types, count, regions
and uptime above **are** verified from `terraform/` and the deployment record; the *dollars* are
list-price reasoning and must be confirmed against the actual AWS bill before anything is bought.
**R3 applies with full force: this is spend, and it is Larry's, every time.**

**What F still costs, unchanged from C:** a fifth machine to maintain that is not part of the net,
a runner registration to keep alive, the self-hosted-runner-executing-PR-code shape, and the R1
dilution — a runner this session provisions and can reach is a weaker witness than one it cannot
touch.

### D. Rig only — delete CI

Saves everything and gives up R1. The coordinator would again be the sole producer and sole judge
of every acceptance number. **Given that this project's worst incidents this month were
*coordinator judgment* errors and not test failures** — accepting `PR #178` against a criterion
its in-process tests could satisfy and production could not; merging `#178` and `#182` the same day
without composing them — removing the one structural check on the coordinator is the wrong trade
at almost any price.

### E. Make the repo public

Actions minutes are free for public repositories. **`CLAUDE.md` says the repo is private and to
keep it that way**, so this is not a CI decision — it is a project-disclosure decision that happens
to have a CI consequence, and it belongs to Larry entirely.

## 8. Recommendation

**Do B now, independently of the budget question.** It is free, reversible, needs no authorisation,
and removes the half of the spend that buys nothing. Whatever is decided about hosting is decided
against a halved baseline, which is the honest number to decide against.

**Then decide A vs F deliberately** — not A vs C — **with F's operational cost priced rather than
assumed.** After B,
the current procedure costs roughly one suite run per merged PR — the rate at which this project
actually merges, not the rate at which builders push. That may well be affordable on A, which
would make C's maintenance burden unjustified. **That arithmetic cannot be done before B, because
today's number is dominated by runs nobody reads.**

**Not recommended: D**, for the reason in §7. **Not assessed here: E**, because it is not a CI
question.

**Separately, and larger than everything above: read the AWS bill.** §7F establishes that four
on-demand instances have been running continuously for 161 hours across four regions with no
Savings Plan and no spot, and that **nobody has ever looked at what they cost.** That number is
plausibly several times the $20 this document was opened about. **Whatever is decided about CI, the
T0 fleet is the bigger line and it is unmeasured** — and a Savings Plan, if one is ever bought,
should be sized against *that*, with CI riding it rather than justifying it.

## 9. What is open

| | owner |
|---|---|
| The `$20` budget: raise, hold, or hold-and-cut-usage | **Larry (R3)** |
| Whether to move off GitHub-hosted at all | **Larry**, informed by §7F (§7C is the weaker AWS option) |
| **Whether to buy a Savings Plan, and sized against what** | **Larry (R3)** — see §7F: the T0 fleet, not CI, is the workload that fits one |
| **Reading the actual AWS bill for the T0 fleet** | unassigned, and it is the largest unmeasured number in this document |
| Repo visibility | **Larry** |
| ~~The trigger change (§7B)~~ | **DONE 2026-08-02** — `types: [labeled]` + a `verify` gate. See §7B. |

---

*Written 2026-08-02 by the coordinator session, after Larry's billing screenshot made the spend
visible. The measurements in §4 are reproducible with `gh run list` and the org billing page; the
$9.31 is the only figure taken rather than derived.*
