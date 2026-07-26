# Devnet Finality-Stall Recovery Runbook (M10-T0-2)

**Scope:** devnet / internal-net grade. This is the *recovery* half of Ebb-and-Flow —
the half the Crosslink feature net left undesigned, which stalled its BFT finality
from ~2026-05-12 through late July with no clean way back
(qumbra-design `consensus-and-network.md` §4 status update, 2026-07-24). The
*degradation* half — the PoW chain keeps producing in probabilistic mode when the
committee stalls — is **frozen §4** and is not what this runbook changes. Nothing
here alters quorum, tombstone, or slash semantics; those are read-only.

Everything below is implemented in `qlab-node::recovery`, `qlab-node::telemetry`,
and the `qlab-p2p::adapter` glue, and exercised end-to-end by
`finality_stall_degrade_committee_restart_recovery`.

---

## 1. What a stall looks like

A Qumbra node is always in one of two finality regimes
(`qlab_devnet::ebbflow::FinalityStatus`):

- **Final** — the tip is within `DEGRADED_MODE_LAG_BLOCKS` (= 16, = 2× cadence) of
  the finalized head.
- **Degraded** — nothing has finalized yet, or the tip has outrun the finalized
  head by more than that. The chain is *still producing blocks* (liveness is never
  hostage to the committee); it just has no fresh finality.

A stall is **normal and safe** on its own — it is the design working. The failure
mode Crosslink hit was not the stall; it was having no designed way to *recover*
from one, so operators improvised (manually designated canonical blocks for reward
rounds, a user-led forking tool). Qumbra recovers by process, not by improvisation.

## 2. Detect it — `/v1/telemetry`

Poll the versioned telemetry endpoint (`qlab_node::telemetry::Telemetry`):

| Field | Meaning | Stall signal |
|---|---|---|
| `finality_status` | Final / Degraded | flips to **Degraded** |
| `stall_depth` | `tip − finalized` (blocks) | climbs past 16 and keeps rising |
| `last_finalized_age_secs` | chain-time since the last finalized checkpoint | climbs without resetting |
| `finalized_height` | finalized head | **stops advancing** while `tip_height` climbs |
| `peer_count` | connected peers (injected from P2P) | if ~0, the problem is the *network*, not the committee |
| `mempool_size` | pending txs | tends to grow during a stall (anchors age out) |
| `epoch` | current committee epoch | which roster is authoritative |

`stall_depth` and `last_finalized_age_secs` are the same stall in the two units an
operator reasons in — "how many blocks behind" and "how long stuck." Age is derived
from block timestamps (chain-time), so it is deterministic, not wall-clock.

> **Cold-start caveat (added 2026-07-25, M10-T0-5 / PR #72).** The two units agree
> only once something has been finalized. On a node that has **never** finalized a
> checkpoint — a fresh net, or a node reopened from disk before the first re-gossip
> (the finality tracker is not persisted, by design) — `last_finalized_age_secs`
> reports **0**, because there is no finalized head to measure an age from. It does
> not mean "healthy and current." Before the T0-5 fix this field fell back to genesis
> and printed an absolute epoch (Phase B-lite logged `age_s=1784917791`), which was
> worse: nonsense rather than honest. **Key the cold-start alarm on `finalized_height
> == None` (`final=-` in the telemetry line) together with a climbing `stall_depth`,
> not on age.** Once a first checkpoint finalizes, the two units track each other
> again and everything below applies unchanged.

## 3. Triage — is it the committee or the network?

1. **`peer_count` near zero** → this node is partitioned. Fix connectivity first;
   finality will resume on its own once checkpoints propagate again. (Recorded M9
   gotcha: announce-flood can drop orphan blocks without kicking sync — a
   partitioned node recovers through the header-sync path.)
2. **Peers healthy, `finalized_height` frozen** → the committee is not reaching
   quorum. Check, per the current `epoch`'s roster:
   - How many finalizers are **up**? A stall means fewer than the ⅔+1 quorum
     (15 of 21 frozen) are voting.
   - Are members **jailed** (downtime, `MemberStatus::Jailed`) or **tombstoned**
     (equivocation, permanent)? Tombstoned members never count toward quorum; if
     tombstones pushed the active set below quorum, recovery needs new members
     staged at the next epoch boundary — a governance action, not a restart.
3. **Malformed-input safety:** the finality path rejects bad votes / evidence
   rather than panicking (a distinct Crosslink incident was a finality-path panic
   on malformed input). Checkpoint, evidence, and telemetry wires are versioned and
   reject unknown-version / trailing bytes (§0). A single bad message cannot wedge
   a node.

## 4. Recover — restart the finalizers

The common case: finalizer processes went down (crash, deploy, OOM) and the active
set dropped below quorum. Bring them back:

1. **Restart each downed finalizer.** It reloads its persistent ledger
   (`FinalizerState::from_bytes`, written before each vote was broadcast) via
   `Finalizer::restore`. It now knows its **last-voted slot** and resumes on the
   next cadence slot **without operator surgery** — no manual slot bookkeeping.
2. **Catch-up finalization.** Once ≥ quorum finalizers are back, propose the newest
   available checkpoint: the highest cadence multiple ≤ tip (`recovery::catch_up_slot`).
   The strictly-advancing finalization rule lets this **jump straight past the
   stalled intermediate slots** — there is no per-slot back-fill and, critically,
   **no retroactive manual canonical-block designation** (the Crosslink
   anti-pattern). Finality advances from the old head directly to the recovery slot;
   `finality_status` returns to **Final** and `stall_depth` collapses.
3. **Verify** via `/v1/telemetry`: `finalized_height` jumped, `finality_status` =
   Final, `stall_depth` small.

### The never-double-sign invariant (why restart is safe)

A restarting finalizer must never sign a checkpoint that *conflicts* with one it
already committed to for a slot — that pair of signatures **is** an equivocation
proof and trips the frozen §4 tombstone + slash. `Finalizer::sign` enforces this
from the reloaded ledger: it will re-emit the *same* vote for a slot (idempotent
after a crash), but **refuses** (`SignRefusal::WouldEquivocate`, no signature
produced) a conflicting one. The recovery-aware proposer
(`NodeAdapter::make_checkpoint_guarded`) simply drops a refusing finalizer's vote.

**Operator rule:** the ledger MUST be persisted (write-ahead + fsync) *before* the
corresponding vote leaves the process. Crash-after-persist re-emits the same vote;
crash-after-broadcast-before-persist is the only window this guard cannot close on
its own — write-ahead the slot to shrink it to nothing.

## 5. Rewards during a stall — no manual canonical designation

**Degraded-mode accounting (devnet-grade, testnet-tunable — NOT frozen; coordinator
stamp 2026-07-24):** committee rewards accrue **only for finalized checkpoints**
(`recovery::committee_accrual_finalized`). A stall means **zero committee income for
the stalled span**. The unfinalized span's 15 % committee share is simply not paid
out during the stall; when recovery finalizes the span, its accrual advances
normally. Distribution details are a ledger question M11+ revisits.

This is the deliberate opposite of the Crosslink episode, where reward rounds were
settled against *manually designated* canonical blocks. Qumbra pays the committee
for finality it actually produced — no human in the reward path, no retroactive
canonical choice.

## 6. Quick reference

| Symptom | Check | Action |
|---|---|---|
| `finality_status` = Degraded, `peer_count` ≈ 0 | network | fix connectivity; finality self-resumes |
| Degraded, peers OK, finalizers down | committee liveness | restart finalizers → catch-up finalize |
| Degraded, active set < quorum from tombstones | roster | stage new members at next epoch boundary (governance) |
| A restarted finalizer refuses to vote a slot | `SignRefusal::WouldEquivocate` | expected — it already committed a different checkpoint there; do **not** override |
| Committee income flat during stall | by design | accrues on recovery once the span finalizes |

## 7. Halt-height upgrade — the operator procedure (issue #74)

An upgrade is not a stall, and the two must never be confused: a stall is
`Degraded`, an upgrade is `Halting` then `Halted`. This section is the procedure an
operator executes from this document alone.

### 7.1 What a halted node looks like

A halted node is **alive**. It serves RPC and telemetry, it just stops advancing:

```
TELEMETRY tip=16 final=8  stall=8 age_s=600 diff=… peers=3 mempool=0 epoch=0 regime=Halting halt=16
TELEMETRY tip=16 final=16 stall=0 age_s=0   diff=… peers=3 mempool=0 epoch=0 regime=Halted  halt=16
```

- `halt=<H>` — this release is scheduled to stop at height H. `halt=-` means it has
  no upgrade scheduled.
- `regime=Halting` — the tip has reached H, but **H's checkpoint has not finalized
  yet**. Do **not** swap binaries.
- `regime=Halted` — H is finalized. The upgrade boundary is a finalized boundary;
  everything pre-halt is final by construction. It is now safe to swap.
- `tip` stops moving at exactly H and never passes it.

### 7.2 Telling `Halting` from stuck

This is the distinction that matters most, because they look similar from a
distance and the responses are opposite.

| | `Halting` | Stuck (`Degraded`) |
|---|---|---|
| `halt=` | the scheduled height | `-` |
| `tip` | pinned at exactly `halt` | still climbing |
| What it means | the net is waiting for the boundary to finalize | the committee is not finalizing at all |
| What to do | wait; if it does not clear in ~2 cadences, treat it as a committee-liveness problem (§3–§4) and **do not upgrade** | §3 triage |

A net that sits in `Halting` is telling you something true: fewer than quorum
members are able to sign the boundary checkpoint. That is a reason not to upgrade
yet, not a reason to force the upgrade through. Swapping binaries out of `Halting`
means swapping across an **unfinalized** boundary, which is exactly the property
the halt height exists to guarantee you never have to do.

### 7.3 Before the height — check every node

```
qumbra-node halt-status --config <node.toml>
```

prints the release name, the halt plan, the revision identifier, the
frozen-parameter digest, the post-halt rule domain, and any on-disk halt marker. It
**exits non-zero** if this binary would refuse to start. Run it on every node
before the upgrade window, and confirm:

- every node reports the **same** `halt plan` height;
- every node reports the **same** frozen digest (a node reporting a different one
  is running different consensus constants — stop and investigate);
- the revision identifier matches the announced revision document.

There is no way to change the halt height on a running node. It is a compile-time
release constant; the only way to move it is to deploy a different binary.

### 7.4 At the height

1. Watch until **every** node you control reports `regime=Halted` at an
   **identical** `tip` and `final`. Any disagreement about the boundary is a stop —
   do not proceed.
2. Each halted node writes `halt.marker` into its data dir recording the height,
   the revision that halted it, and that revision's frozen digest. This is your
   evidence the halt happened, and it is what the new binary is checked against.
3. Stop the node, swap the executable, start it. The data dir is **not** wiped: the
   upgraded binary opens the persisted chain at tip H and continues. There is no
   re-sync from genesis and block H is not re-mined.

### 7.5 If the new binary refuses to start

This is the mechanism working. Read the error:

| Error | Meaning | Action |
|---|---|---|
| `resumes past the halt at height H but carries NO revision` | the binary would resume without a revision document (H4) | you have the wrong build; get the release that carries the revision |
| `this node halted at height H … but it declares resumes_from=None` | this binary is not the release that follows this halt — including the case of downgrading to the pre-upgrade binary | deploy the release that follows the halt at H |
| `revision \`X\` declares digest A but this binary's frozen constants digest to B` | a FROZEN v1.0 value moved without a revision describing it, or a revision was copied across a change it does not describe | **stop.** Do not deploy. This is the undocumented-parameter-change alarm |
| `halt height H is not a multiple of the checkpoint cadence 8` | the release's halt height is off the grid | wrong build; the boundary would not be a finalized boundary |

Restarting the **same** halted binary is always allowed — you must be able to stop
and inspect a halted node.

### 7.6 After the swap

- Finality resumes only when **≥⅔ of the committee** (quorum 15 of 21) is on the
  new binary. Below that, the net stays where it was rather than limping forward on
  a minority committee. `final` not advancing with 11 keys upgraded is correct, not
  a fault.
- **Old-binary miners will keep producing blocks past H, and that is expected.**
  `committee-and-governance.md` §4 is explicit about it: unlike pure BFT, the
  hybrid chain does not simply stop. Those blocks can never finalize; the fork
  resolves to the checkpointed branch once miners follow the finality signal. Do
  not treat a growing un-upgraded branch as an incident. **Do** treat it as an
  incident if that branch ever *finalizes* above H — see §7.8.
- A committee member that mined past H on the old binary and **voted** there has
  burned those slots: its never-double-sign ledger will refuse to vote for the
  upgraded branch at the same heights, and the member simply contributes nothing
  until the branch passes them. This is correct, and it is an argument for halting
  cleanly rather than mining through.

### 7.7 Standing an upgrade down

A scheduled upgrade is cancelled by deploying a release whose halt plan is
`CANCELLED`, before the height is reached. It is a binary swap like any other —
there is deliberately no runtime switch. A cancelled release reports

```
halt plan:    CANCELLED — the upgrade at height 16 was stood down (<reason>)
```

on its startup banner and `halt=-` in telemetry, and it mines and finalizes
straight through the cancelled height. The cancelled height stays on the banner on
purpose, so you can tell "I deployed the stand-down" from "I forgot to deploy the
arming".

### 7.8 🛑 Stop-everything conditions

Preserve state, capture logs from every node, do not patch and continue:

- two conflicting checkpoints finalized at the same height;
- any reorg past a finalized checkpoint;
- an un-upgraded branch finalizing above H;
- nodes disagreeing about the boundary block at H.

These are the failures the halt-height mechanism exists to prevent. Everything else
in this section is operations; this is an incident.

### 7.9 Quick reference

| Symptom | Check | Action |
|---|---|---|
| `regime=Halting`, tip pinned at `halt` | boundary not final yet | wait; do **not** swap binaries |
| `regime=Halting` for > ~2 cadences | committee liveness (§3) | triage as a stall; do **not** upgrade |
| `regime=Halted`, identical tip/final everywhere | boundary finalized | swap binaries |
| New binary exits at startup | read the error (§7.5) | usually the wrong build — the gate is working |
| `final` flat after the swap | how many keys upgraded? | below quorum 15 → expected; upgrade more |
| A peer's tip climbing past `halt` | an old-binary miner | expected (§4); watch that it never *finalizes* |
| An un-upgraded branch finalizes above H | — | 🛑 stop everything, preserve state |
