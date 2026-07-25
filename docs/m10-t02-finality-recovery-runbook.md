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
