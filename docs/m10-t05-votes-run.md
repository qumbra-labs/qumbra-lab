# M10-T0-5 vote-aggregation — LOCALHOST/DOCKER run doc

> **Scope label: LOCALHOST/DOCKER.** Docker-compose rehearsal of the cross-node
> vote-aggregation protocol (issue #70) on one dev rig. **NO WAN-latency claims.**
> The latency-sensitive measurements — checkpoint cadence under real RTT, the LWMA
> difficulty trace at WAN pacing, and the **≥48 h** duration bar — remain owed to
> **Phase B-WAN** (the 4-VPS run, gated on Larry's VPSes). What this run establishes:
> with the fix, the real 21-key **6/5/5/5** split **finalizes checkpoints** across 4
> nodes, and the B-lite-deferred §4 (partition → heal) and §5 (committee stall →
> recovery) scenarios now behave correctly.

## Rig + provenance (bench discipline §2)

| Field | Value |
|---|---|
| Repo rev | `claude/m10-t05-votes` (base main `ec98dc0`); final SHA stamped at PR |
| Host | Apple M5 Max, 36 GiB |
| OS | macOS (Darwin 25.5.0) |
| Container runtime | Docker Desktop (Engine 29.6.2, Compose v5.3.1), aarch64 Linux VM |
| RandomX | `randomx-rs` 1.4.1 (light mode) |
| Block time | 75 s (FROZEN, consensus-parameters §2) · Mining clock `WallClock` |
| Power state | AC power |

## What this baton built (issue #70 §2)

Cross-node checkpoint-vote **accumulation**: partial vote sets from the 6/5/5/5 split
travel as a new `CheckpointVotes` (0x0024) push-gossip message; each node accumulates
verified, active, de-duplicated votes per checkpoint variant in a bounded `VoteTally`
(new, `qlab-devnet`) until the distinct-active count reaches quorum (15), then finalizes
through the **unchanged** `try_finalize` (the sole quorum gate — the tally only
*accumulates*, never lowers the bar, S4). Local votes now join the tally + gossip (were
dropped); the scoring bug that banned honest partial-set senders is fixed (S5); the binary
signs through the persisted never-double-sign `Finalizer` (S7) and periodically re-dials
peers so a healed partition reconnects without a restart (S9); telemetry `age_s` is honest
when nothing is finalized (S8).

### Pinned caps (task-book S6 — named, tested; testnet-tunable, NOT frozen)

| Constant | Value | Bound |
|---|---|---|
| `MAX_TALLIED_SLOTS` | 8 | distinct checkpoint heights held at once (newest kept) |
| `MAX_VARIANTS_PER_SLOT` | 4 | distinct checkpoint variants per height |
| `TALLY_TIP_SLACK` | 8 (= cadence) | heights above local tip still tallied |

Window: only heights in `(finalized, tip + slack]`; entries dropped on finalization or
when they fall behind the finalized head. A hostile peer spraying vote sets for arbitrary
heights/roots cannot grow node state past these caps (asserted in `qlab-devnet` tally
tests). The tally itself is **not persisted** — it rebuilds from re-gossip (S7).

## Topology (unchanged from B-lite)

N=4, committee 21 keys split **6/5/5/5** (node0=00..05, node1=06..10, node2=11..15,
node3=16..20). No node holds ≥ quorum 15 — the whole point.

Raw telemetry for every scenario below is committed at
[`docs/m10-t05-votes-evidence.log`](m10-t05-votes-evidence.log).

## Scenarios

### 0. Genesis rehearsal — ✅ PASS

In-container genesis hash `4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3`
== pinned T0 genesis. 4 nodes up, full mesh (6 connections/node).

### 1. Distributed finality FORMS (the headline fix) — ✅ PASS

The B-lite headline finding was `final=-`, `regime=Degraded` forever (no node holds a
quorum, no cross-node aggregation). With the fix, finality forms and advances on the
cadence grid — **no node holds ≥ quorum 15**:

```
t+120s  node0..3  tip=1  final=0  stall=1  regime=Final      ← genesis checkpoint finalized
t+600s  node0..3  tip=8  final=8  stall=0  regime=Final      ← height-8 cadence checkpoint
```

All four nodes finalize the same height in lockstep; the 6-, 5-, 5-, 5-key slices
accumulate across `CheckpointVotes` gossip to the 15-of-21 quorum. `regime=Final`
throughout (stall never exceeds `DEGRADED_MODE_LAG_BLOCKS`=16 while finality keeps pace).

### 4. 2+2 partition → heal (B-lite-deferred; now ✅ PASS)

Partition A={node0,node1}=11 keys | B={node2,node3}=10 keys applied at tip=9, final=8.
Docker network split confirmed: `qumbra_t0`={node0,node1}, `qumbra_t0_sideb`={node2,node3}
— separate networks, no cross-talk; each side mines independently.

**Stall (both sides < quorum 15):** `final` stayed frozen at **8** for 13 blocks of
independent mining, *including past the height-16 checkpoint slot*:

```
partition@tip=9  → tip=16 final=8 (slot 16 reached, NEITHER side finalized it)
                 → tip=22 final=8 stall=14  (11 and 10 keys, both < 15)
```

STOP-check armed throughout (`final` > 8 ⇒ abort): **never tripped** — no side finalized
without quorum, no two checkpoints at one height.

**Heal (`soak.sh heal` = `docker network connect`, NO process restart):**

```
t+45s   peers 6 → 10–12   ← periodic re-dial (S9) reconnected the split sockets
t+90s   all 4 nodes tip=23 final=8   ← fork-choice converged the two forked chains
t+180s  all 4 nodes tip=24 final=24 stall=0 regime=Final   ← FINALITY RESUMED
```

Finality jumped **8 → 24 directly** (the partition-era slot 16 forked and never reached
quorum; strictly-advancing catch-up skips it). Recovery required **no restart** — re-dial
reconnected the peers automatically, exactly the B-lite 🟡 dial-once gap this baton closes.

### 5. Committee stall → recovery (B-lite-deferred; now ✅ PASS)

Stop node1+node2+node3 (16 keys offline) at tip=26, final=24 — node0 holds only 6 < 15.

**Stall:** node0 mined on alone; `final` stayed frozen at **24** past the height-32 slot:

```
node0  tip=32  final=24  (slot 32 reached, node0's 6 keys < 15 → not finalized)
```

STOP-check (`final` > 24 ⇒ abort): **never tripped**.

**Recovery (`soak.sh committee-recover` = restart the 3 nodes; open==replay from disk):**

```
restart   node1 tip=26 final=-   node2 tip=26 final=-   node3 tip=24 final=-   (peers 1–3)
t+60s     all 4 tip=32   restarted nodes final=- (still Degraded), peers reconnected
t+120s    all 4 tip=34 final=32 stall=2 regime=Final   ← COMMITTEE RE-FORMED, finality caught up
```

The restarted nodes reopened with **`final=-`** — the finality tracker is not persisted (S7 by
design; it rebuilds from re-gossip). Once re-dial reconnected them and they header-synced to
tip=32, all four re-proposed slot 32; the accumulated votes reached quorum 15, node0 finalized 32
and served the full set, and the restarted nodes' trackers rebuilt to `final=32` — finality caught
up 24 → 32 over the stalled span. This directly demonstrates the S7 "finality rebuilds from
re-gossip" property in a real restart.

### 6. Steady soak (≥2 h) — ✅ PASS

`soak.sh status` sampled every 5 min for **135 min** (≥2 h ✓), 2026-07-25 20:43:50 → 22:59:06,
27 samples, all 4 nodes up throughout. A finality-regression STOP-check (`node0 final` decreasing
⇒ abort) ran every sample and **never tripped**.

| Metric | Result |
|---|---|
| Duration | 135 min continuous (≥2 h ✓), 27 samples |
| Finality | `final` advanced **32 → 232** — **25 checkpoints finalized on the cadence grid**, monotone |
| Blocks | tip 34 → 245 |
| Tip consistency | **≤ 1-block spread** across all 4 nodes the whole run (no fork) |
| Regime | `Final` on **107 / 108** node-samples |
| LWMA difficulty | 84 → 2156 (climbing as LWMA damps the 4-miner localhost block rate toward 75 s) |
| Peers | node0 16, others 6 (stable) |
| Consensus misbehavior | **none** (no fork, no double-finalization, no finality regression, no crash) |

**Honest note — one transient `Degraded`:** at t+50 min node3 logged `stall=17` (> the 16-block
`DEGRADED_MODE_LAG_BLOCKS`) for a single sample — during the fast multi-miner LWMA ramp the tip
briefly outran the cadence finality by 17 blocks. **Finality itself never stalled** (`final` kept
advancing 120 → 232), and the node was back to `Final` at the next sample. This is the known
localhost multi-miner artifact (all 4 nodes mine in parallel until difficulty climbs), not a
finality failure — the same 🟢 ramp B-lite recorded.

## Acceptance suite

**Full unfiltered `cargo test --release --workspace --no-fail-fast`: 569 / 569, 0 failed**
(single run; baseline 548 post-#71 + **21 new tests**). New/updated tests: `VoteTally`
(7, incl. late-vote accumulation + both cap bounds) · 6/5/5/5 reaches quorum · partials
don't penalise · late votes learnable (blocker-3 lock) · forged/unknown/dup never tally ·
tombstoned excluded · restart-never-equivocates (run path) · re-dial reconnect · telemetry
age 0/`-` · golden `CheckpointVotes` byte-vector + reject-unknown/trailing.

## STOP-POINT watch (§3)

- Two different checkpoints finalized at one height: **not observed**.
- Finality advancing without quorum: **not observed** (partition STOP-check armed).
- No signed-preimage / `Checkpoint`-shape / FROZEN-constant change.

## Honest remainder (owed to Phase B-WAN / follow-ups)

- WAN-only: real RTT, LWMA at WAN pacing, ≥48 h telemetry — Phase B-WAN (4 VPSes).
- The finality **tracker** is not persisted (S7 by design — rebuilds from re-gossip): a
  solo reopened node reports no finalized height until a checkpoint is re-gossiped
  (immediate in a live mesh; documented, not a gap).
- Relay is direct-push (converges on "tally grew"); an inv/getdata vote path
  (`InvKind::CheckpointVotes=4`) is reserved but unused.
- Zero-contact touch (coordinator-approved): one `qlab-bench` n7soak case updated to the
  S5-correct scoring (well-formed sub-quorum not penalised; forged still penalised).
