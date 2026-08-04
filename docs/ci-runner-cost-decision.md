# Where the CI suite runs, and what it costs

**Status: one half decided, one half open.** *(Amended 2026-08-02: option F added at Larry's
suggestion — EC2 on-demand under a Savings Plan — which the first version omitted, and which
displaces spot as the AWS option worth pricing. The amendment also surfaced that the T0 fleet's own
on-demand cost has never been measured. Amended again the same day: option G — EKS with runners as
pods — assessed and not recommended, and assessing it surfaced a sizing lever that applies to every
option.)* The architecture is settled and stays settled. The
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

### G. AWS EKS, runners as pods (actions-runner-controller)

**Raised by Larry, 2026-08-02.** Assessed against the same four axes, and the answer turns on what
the workload actually is rather than on anything wrong with EKS.

**What it would genuinely buy.** `actions-runner-controller` gives **ephemeral runners** — a fresh
pod per job, destroyed after — which is a materially better security posture than F's long-lived
self-hosted runner, because the "self-hosted runner executing PR code" shape in §7C/§7F is largely
a *persistence* problem. It is declarative, it scales node capacity to zero between jobs, and it is
the standard answer at organisations running hundreds of jobs an hour.

**Why it does not fit here, and the number is not close.** **An EKS control plane bills
continuously and cannot scale to zero** — on the order of $70–75 a month at list price, *before a
single node runs a single test*. That is **roughly 3.5× this document's entire $20 CI budget**, to
serve **one job, once or twice a day, that needs no scheduling decisions at all.**

Kubernetes solves multi-tenancy, bin-packing and fleet orchestration. **This workload has one
tenant, one pod, and nothing to pack.** The suite is a single serial process on a single machine;
there is no scheduling problem for a scheduler to solve.

**And the operational surface is larger than F's, not smaller.** A cluster, ARC and its webhooks,
node groups or Karpenter, IRSA, plus EKS's own forced Kubernetes version upgrades — against F's
"one instance, start it, stop it". §7C's and §7F's R1 objection applies unchanged: a cluster this
session provisions and can reach is a weaker witness than a runner it cannot touch.

**Where G would become right:** if CI volume grew to many jobs an hour, if several repositories
shared it, or if a cluster already existed for another reason. **None of those is true**, and the
first is the opposite of the direction §7B just moved in.

**The ephemeral-runner benefit is separable, and that is the useful part of the question.** F can
have most of it without a cluster — an instance started per run from a launch template and
terminated after, or a container task on **ECS/Fargate**, which has **no control-plane fee at all**
and supports arm64. If the reason to consider G is *ephemerality* rather than *Kubernetes*, Fargate
is the cheaper way to buy it and belongs in the F comparison rather than as its own option.

**Not recommended — on the premise that the cluster would exist for CI.** Not because EKS is
wrong, but because the fixed control-plane cost alone exceeds the total budget this document is
about, for a workload with no scheduling problem.

#### 🔴 That premise changed while this section was being written

Larry, 2026-08-02: *"I could take a lot of the EC2 instances out of the `default` AWS profile and
run them in EKS instead."*

**If a cluster is going to exist anyway, its control-plane fee is not attributable to CI, and G's
main objection above dissolves.** This is structurally the same argument as §7F's Savings Plan
conclusion: the fixed cost is justified by the *continuous* workload, and CI rides it as a side
effect rather than having to justify it. **G is not disqualified; the version of G assessed above
simply is not the version on the table.**

What G would then be, honestly compared against F:

| | F (on-demand + start/stop) | G (existing cluster + ARC) |
|---|---|---|
| control-plane cost attributable to CI | none | **none, under the new premise** |
| runner lifetime | long-lived instance, or per-run launch template | **ephemeral pod per job — better** |
| operational surface added *by CI* | one instance + start/stop | **an ARC install on a cluster already being run** |
| R1 independence | diluted (§7C) | **diluted the same way, no better and no worse** |

**On this premise G becomes the stronger option**, because ephemeral runners are the right answer
to the persistence half of the self-hosted security shape, and under a shared cluster they cost
almost nothing extra.

**What is needed before deciding, and it is not an opinion:** the actual list of what is in that
profile, what each instance does, and whether any of it is stateful. This document cannot assess a
consolidation it has not seen.

#### 🔴 The four T0 hosts must not be part of that consolidation

Stated here because it is the one migration that would be actively wrong, and cost is not the
reason.

**The T0 fleet is four `t4g.small` in `us-east-1`, `eu-west-1`, `ap-southeast-1` and
`ap-northeast-1` — three continents — and the geography IS the experiment.** The Phase B-WAN
evidence pack rests on a **measured 68–223 ms RTT baseline** and on distributed finality forming
across real intercontinental latency with no node holding a quorum. **An EKS cluster is regional.**
Consolidating those four into one cluster collapses the RTT to intra-region single-digit
milliseconds and **destroys the property the 48-hour soak was run to establish** — while leaving
the net apparently healthy, which is this project's recurring shape once more.

They are also live: the net is finalizing right now, and `qumbra-deploy`'s **R3 applies —
*"changing instance types, adding hosts... ask, every time, and never infer approval from an
earlier yes."*** Consolidating them is a destroy-and-recreate.

**Everything else in the profile is a fair candidate. These four are not**, and if they were in the
count that motivated the idea, the arithmetic needs redoing without them.

### The sizing lever nobody has pulled, which applies to A, C, F and G alike

Found while assessing G, and it is worth more than the choice between them.

**`--test-threads=1` means core count cannot help** — the workflow's own header records this:
*"an arm64 core is ~1.8× slower than the M3 Max at single-threaded work, and `--test-threads=1`
means core count cannot help. 34 minutes is this runner's floor; there is no cache fix to find."*

The measured profile of the suite is therefore:

| | measured | source |
|---|---|---|
| peak RSS | **16.33 GB** | `/usr/bin/time -v` on the `PR #202` and `#195` runs |
| wall clock | **34–38 min** | same runs |
| useful parallelism | **1** | `-- --test-threads=1`, non-negotiable per `CLAUDE.md` §5 |

🔴 **The current runner is 8 cores. The suite can use one.** Seven of them are paid for and idle
for 35 minutes, every run. The binding constraint is **memory — ~32 GB to hold a 16.33 GB peak with
headroom** — and single-thread speed. Not core count.

**So on any self-hosted option, the instance to price is a few fast cores with 32 GB, not an
8-core.** A `4 vCPU / 32 GB` Graviton type would run this suite at the same wall clock as an
`8 vCPU / 32 GB` one and cost meaningfully less. **This lever has never been pulled and is
independent of where the runner lives** — it is a property of the workload, established by
measurement, and it is the reason a per-minute comparison between hosting options is the wrong
first question.

*(It cannot be pulled on option A: GitHub's larger-runner catalogue is sized by core count, so
paying for 8 cores is the price of getting 32 GB there.)*

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

**Not recommended: D**, for the reason in §7. **G is now conditional, not rejected** — its control-plane fee is ~3.5× this whole budget *if CI
must justify it*, and **not chargeable to CI at all if the cluster exists anyway**, which Larry
raised as a live possibility on 2026-08-02 (§7G). On that premise G overtakes F, on ephemeral
runners. **The four T0 hosts are excluded from any such consolidation — see §7G, and the reason is
correctness, not cost.** **Not
assessed here: E**, because it is not a CI question.

**And before pricing any of them, pull the sizing lever.** §7G's closing subsection establishes by
measurement that the suite uses **one core** and needs **32 GB**, so seven of the current runner's
eight cores are paid for and idle every run. **The instance to price is `4 vCPU / 32 GB`, not
8-core** — which changes the arithmetic of C, F and G before the choice between them is even made.

**Separately, and larger than everything above: read the AWS bill.** §7F establishes that four
on-demand instances have been running continuously for 161 hours across four regions with no
Savings Plan and no spot, and that **nobody has ever looked at what they cost.** That number is
plausibly several times the $20 this document was opened about. **Whatever is decided about CI, the
T0 fleet is the bigger line and it is unmeasured** — and a Savings Plan, if one is ever bought,
should be sized against *that*, with CI riding it rather than justifying it.

## 9. What is open

| | owner |
|---|---|
| ~~The `$20` budget: raise, hold, or hold-and-cut-usage~~ | **RESHAPED 2026-08-03 — see §10.** The product-level stop was the wrong shape, not just the wrong size: it coupled the free pre-filter to the paid suite's cap. Split into a SKU-level hard stop on the runner that actually spends. The open half is recalibrating the $50 after a week of label-gated cadence — **Larry (R3)** |
| Whether to move off GitHub-hosted at all | **Larry**, informed by §7F (§7C and §7G are the weaker options) |
| **Sizing any self-hosted instance at 4 vCPU / 32 GB rather than 8-core** | coordinator, once a host is chosen — measured, see §7G |
| **Whether the `default` profile's other EC2 workloads consolidate into EKS** | **Larry** — not a CI decision; CI only rides the outcome (§7G) |
| Confirming the T0 four are excluded from that consolidation | **Larry (R3)** — §7G says why they must be |
| **Whether to buy a Savings Plan, and sized against what** | **Larry (R3)** — see §7F: the T0 fleet, not CI, is the workload that fits one |
| **Reading the actual AWS bill for the T0 fleet** | unassigned, and it is the largest unmeasured number in this document |
| Repo visibility | **Larry** |
| ~~The trigger change (§7B)~~ | **DONE 2026-08-02** — `types: [labeled]` + a `verify` gate. See §7B. |

## 10. The stop-usage blast radius, and the SKU split (2026-08-03)

**The defect this section fixes is a shape, not a number.** The `$20` budget was `ProductPricing`
on `actions` with `prevent_further_usage: true` — so the day it trips, **every** Actions workflow
stops, including `prefilter.yml`, which runs on standard runners inside the plan's included
minutes and costs nothing. The cheap guard dies with the expensive suite. And the failure is
silent: workflows simply stop starting, nothing alerts the fleet, and the first symptom is four
batons queueing for the rig again — **the exact state this CI exists to remove**, restored by the
budget that was supposed to protect it.

### The numbers, same method as §4

From `gh api /organizations/qumbra-labs/settings/billing/usage` on 2026-08-03:

| | value | how |
|---|---|---|
| August spend at 08-03 | **$14.14 of $20.00** | billing page + usage API agree |
| where it went | **100 % one SKU: `Actions Linux ARM 8-core`** | 1,010 billed minutes ≈ $0.014/min, three usage items ($8.76 + $4.84 + $0.53) |
| standard `Actions Linux` minutes | 87 min, **$0** | inside the plan's included pool — the pre-filter has never cost money |
| headroom remaining | $5.86 ≈ **11 suite runs** at $0.55 each | days, at the post-#210 acceptance cadence |

⚠️ **The last row previously read "≈ 8 suite runs at §4's ~$0.7". Corrected 2026-08-04, twice
over.** §4's figure is **$0.49**, not $0.7 — §4 exists in part to retract the $0.7 that `PR #191`
recorded, so citing it back was a self-citation of a number this document had already withdrawn.
And $0.49 is the wrong figure to reach for anyway: it is a mean over a **pre-#210 population**
that included builder-push runs cancelled early. The right per-run cost is derived from this
section's own rate against this section's own population — see the recalibration below.

So the product-level cap conflated two flows with nothing in common: a paid SKU that is 100 % of
the spend, and a free tier that is 100 % of the always-on guard.

### The split, decided 2026-08-03

| budget | scope | amount | stop usage | job |
|---|---|---|---|---|
| **new** | `SkuPricing` on `actions_linux_8_core_arm` | $50 | **Yes** | the hard stop, on the only thing that spends |
| **reshaped** | `ProductPricing` on `actions` | $60 | **No — alert only** | early warning for anything that is *not* the big runner: storage overage, standard minutes past the included pool |

$50 ≈ **91 suite runs/month ≈ 3 acceptances/day** (corrected 2026-08-04 from "70 ≈ 2–3", same
cause as the row above). **It is an interim guard, not the §8 hosting decision** — recalibrate
after a week of label-gated data, and re-derive entirely if A vs F resolves to a self-hosted
runner.

Applied via the budgets API (needs `admin:org`):

```
POST  /organizations/qumbra-labs/settings/billing/budgets
      {"budget_type":"SkuPricing","budget_product_sku":"actions_linux_8_core_arm",
       "budget_scope":"organization","budget_amount":50,"prevent_further_usage":true, …}
PATCH /organizations/qumbra-labs/settings/billing/budgets/7adffff2-…
      {"budget_amount":60,"prevent_further_usage":false, …}
```

Verification is the same API: `GET …/settings/billing/budgets` must show both rows as above.
One repeatable trick worth recording: **the valid SKU identifiers are not listable anywhere, but a
`POST` with a bogus `budget_product_sku` returns the full legal list in its error message.**

### Recalibration (2026-08-04) — partial, and it says the $50 has no margin

§10 asked for a recalibration after a week of label-gated data. This is **2.3 days**, not a week,
and it is recorded now only because correcting the arithmetic above required deriving the per-run
cost properly. Treat it as an interim reading.

Every `suite-arm64.yml` entry since the gate landed (`c9b5055`, 2026-08-02T01:14:50Z) through
2026-08-04T08:46Z:

```
21m cancelled · 39m · 39m · 39m · 40m · 39m · 38m · 39m · 0m skipped
```

| | value | how |
|---|---|---|
| completed acceptances | **7** | 39.0 min mean, range 38–40 — a remarkably tight distribution |
| cost per acceptance | **$0.55** | $0.014/min × 39.0 min, both from this section |
| elapsed | 55.5 h | gate landed → now |
| **cadence** | **3.03 acceptances/day** | 7 / 2.31 days |
| post-gate spend | $4.12 | 294 metered minutes × $0.014 |
| **projected month** | **~$54** | 91 acceptances × $0.55, plus ~13 cancelled runs × $0.29 |

🔴 **$50 is roughly one month of the observed cadence, with no margin — it will trip near month
end rather than act as a ceiling nobody reaches.** That is not an argument to raise it: a cap that
occasionally trips is doing its job, and the SKU split means tripping it no longer takes the
pre-filter down with it. It is an argument to expect it and to have §8 resolved before it happens.

The `0m skipped` entry is the label gate working correctly — a non-`verify` label fired the
workflow and the job's `if:` declined it, at no cost.

**Method note, because it is the mistake most likely to be repeated.** An earlier reading of this
same data gave **6.9 runs/day** by dividing the run count by the span *between the first and last
run*. That silently excludes idle time — here, a 24-hour gap with no acceptances at all — and
inflates the cadence by more than 2×. Divide by **elapsed wall-clock since the gate**, not by the
window the runs happen to occupy.

⚠️ **One figure in the 08-03 table has already expired.** Standard `Actions Linux` minutes were
`87 min, $0` inside the plan's included pool. As of 2026-08-04 they are **171 min, $1.03** — the
included pool has been exhausted, so *"the pre-filter has never cost money"* is now a statement
about the past. It does not weaken the split; it strengthens it, because the $60 alert-only
product budget is now watching a flow that genuinely spends rather than one that could not.

### One boundary this does not move

`packages` stays at $0 with stop usage **on**. The node image on GHCR is public and public-package
storage is free, so nothing running today is affected — but the day someone pushes a **private**
image, the push will fail on this budget and the error will read like a permissions problem.
Recorded here so that hour is spent on this sentence instead of on GHCR auth docs.

---

*Written 2026-08-02 by the coordinator session, after Larry's billing screenshot made the spend
visible. The measurements in §4 are reproducible with `gh run list` and the org billing page; the
$9.31 is the only figure taken rather than derived. §10 added 2026-08-03 by the reviewer session
(Larry's dispatch) after the second billing screenshot; its figures come from the usage API and
the budgets API, both quoted in place.*
