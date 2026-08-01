# M10-T0-3 Phase B-WAN — the T0 evidence pack (WAN)

> [中文版](m10-t03-phase-b-wan-run-zh.md)

> **SEALED 2026-07-28 07:46Z.** The bar is met: minimum container uptime covered by the archive is **48.01 h**, all four nodes, zero restarts.

Scope label: **WAN**. Four hosts, three continents, real intercontinental latency. This is the run [Phase B-lite](m10-t03-phase-b-lite-run.md) deferred its WAN-only items to, and it is the first time the frozen v1.0 consensus has run unattended for two days on a network it does not control.

**Read the "What this run does not claim" section before quoting anything from here.** Four scenario drills are owed and deliberately not run; the reason is a sequencing decision, not an omission.

## Rig + provenance (bench discipline §2)

| Field | Value |
|---|---|
| Topology | 4 × AWS `t4g.small` (Graviton, arm64, 2 vCPU / 2 GB), Debian 12 |
| Regions | `us-east-1` · `eu-west-1` · `ap-southeast-1` · `ap-northeast-1` |
| Provisioning | Terraform, [`qumbra-deploy`](https://github.com/qumbra-labs/qumbra-deploy) (private), one state, four aliased providers |
| Image | `ghcr.io/lai3d/qumbra-node@sha256:7e4080f3…e60fdea` — **digest-pinned, identical on all four**; GHCR package public, so no host holds a registry credential |
| Genesis hash | `4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3`, pinned and verified on every node |
| Committee | N=21 ML-DSA keys split **6/5/5/5** — **no node holds the quorum of 15** |
| Block time | 75 s (FROZEN, consensus-parameters §2); epoch 1,152 blocks = exactly 24 h |
| Mining clock | `WallClock` (real header timestamps) |
| PoW | RandomX light mode, arm64 |
| Measured RTT | **68–223 ms**, baselined before the run started |
| Run start | containers `StartedAt` **2026-07-26 07:43:00–07:43:05 Z** (= 15:43 +0800) |
| Primary record | each node's own container log, `docker logs -t`, archived to `qumbra-ops/node{0..3}-telemetry-full.log` |

## The bar, and how it is timed

The bar is **≥ 48 h continuous**, and it is timed from the **net**, not from the observer: the containers started 07:43:0xZ, the sampler only at 07:57:19Z. The intervening ~14 minutes are not a gap — they were recovered from the container logs and are documented in `qumbra-deploy/OPERATOR.md` §3.

**The bar is met.** Measured from each container's own `StartedAt` to the last telemetry line archived from it, the four nodes are covered for **48.05 / 48.01 / 48.03 / 48.06 h** — minimum **48.01 h** — with **zero restarts**. The archive was pulled after the mark rather than before it, so the evidence file itself spans the bar; nothing here is extrapolated forward.

## The primary record is the node, not the sampler

This pack is built from the **nodes' own container logs**, not from the 5-minute SSH sampler. That is a deliberate choice and it was load-bearing: the sampler went blind for **10.15 hours** mid-run (see "Observation gaps"), while the container logs did not miss a line.

The reasoning is written up as an adopted design doc — [`qumbra-design/observability-and-evidence.md`](https://github.com/qumbra-labs/qumbra-design/blob/main/observability-and-evidence.md) — whose rule is: *evidence is the node's own durable, archived output; a dashboard is never the evidence.*

Two details make the archive usable, and both are easy to omit:

- **`docker logs -t`.** The `TELEMETRY` line carries no timestamp of its own. Without `-t` there is no time axis and the archive cannot be aligned with anything.
- **`RestartCount` captured alongside.** `restarts=0` is what makes the archive *one continuous record* rather than fragments. Continuity is the bar; nothing else substantiates it.

## Continuity — the property under test

| | node0 | node1 | node2 | node3 |
|---|---|---|---|---|
| container restarts | **0** | **0** | **0** | **0** |
| telemetry lines archived | 3,692 | 3,709 | 3,630 | 3,628 |
| uptime covered by the archive | 48.05 h | 48.01 h | 48.03 h | 48.06 h |
| **finality reversions** | **0** | **0** | **0** | **0** |
| tip reorgs (all depth-1, all near block 89) | 1 | 2 | 1 | 2 |
| `final` at last sample | 2352 | 2352 | 2352 | 2352 |

**No `final` value ever decreased on any node.** That is the R2 STOP-POINT criterion, and it is the single most important line in this pack. All four end at the same `final`.

The tip reorgs are depth-1 and occur in the run's first minutes, before finality had caught up — expected PoW behaviour, not a finality event.

## Distributed finality across three continents, with no node holding a quorum

The property [issue #70](https://github.com/qumbra-labs/qumbra-lab/issues/70) fixed and [Phase B-lite](m10-t03-phase-b-lite-run.md) could only show on localhost: with 21 keys split 6/5/5/5, **finality forms and advances at 68–223 ms RTT** for two days. `final` reached 2352 identically on all four.

## Two epoch boundaries at real WAN pacing

The committee epoch machinery had never crossed a boundary on a live multi-node net. A 48 h run at a 24 h epoch crosses **two**, and both are in the archive.

**Epoch 0 → 1, at `tip=1152`:**

| node | crossing (UTC) | local (+0800) |
|---|---|---|
| node2 | 2026-07-27 06:37:22 Z | 14:37:22 |
| node3 | 2026-07-27 06:37:33 Z | 14:37:33 |
| node0 | 2026-07-27 06:37:42 Z | 14:37:42 |
| node1 | 2026-07-27 06:37:50 Z | 14:37:50 |

**All four within 28 seconds**, across three continents, with no split roster view.

**Epoch 1 → 2, at `tip=2304`:**

| node | crossing (UTC) | local (+0800) |
|---|---|---|
| node2 | 2026-07-28 06:39:08 Z | 14:39:08 |
| node1 | 2026-07-28 06:39:12 Z | 14:39:12 |
| node0 | 2026-07-28 06:40:20 Z | 14:40:20 |
| node3 | 2026-07-28 06:40:27 Z | 14:40:27 |

**All four within 79 seconds.** node3's first `epoch=2` sample already reads `tip=2305` — the telemetry cadence is ~47 s, so it sampled one block after the boundary rather than on it; the boundary is still 2304.

The second crossing matters more than the first for a reason worth stating: it happened **while the operator was not watching for it**, on a net that had already been up for 47 hours, and it required no intervention. The first was anticipated; the second was routine.

> **Correction on record.** This crossing was first reported as 19:23 +0800. That was wrong — 19:23 was merely the first *sample* after the observation blackout described below. The archive gives 14:37. The live view was wrong about a headline result and the archive was right, which is the clearest single illustration of this pack's method.

## LWMA / block production at WAN pacing

Phase B-lite only ever saw localhost pacing. Measured here (node0, 1,707 intervals, target 75 s):

```
mean 86 s   median 60 s   p90 172 s   p99 320 s   max 629 s
```

That is ordinary PoW variance around a difficulty that is tracking: the mean sits above target (retarget lag), the median below, and the tail is long as a Poisson-ish process requires. Nothing here suggests LWMA misbehaving at WAN pacing.

## Finality cadence — and a FROZEN question this run opens

Finality advances on a checkpoint cadence of 8 blocks. Measured (node0, 191 advances):

```
mean 901 s   median 673 s   p90 1802 s   max 3161 s      (nominal 8 blocks ≈ 690 s)
69 of 191 advances jumped more than one checkpoint (steps of 16 / 24 / 32 / 40 blocks)
```

**On the median the committee keeps up exactly** — 673 s against a nominal 690 s. The tail is heavy: better than a third of advances are multi-checkpoint catch-ups.

The consequence is that the net sits in `Degraded` a meaningful fraction of the time:

| | node0 | node1 | node2 | node3 |
|---|---|---|---|---|
| `Degraded` share of samples | 15.4 % | 15.4 % | 14.1 % | 15.2 % |
| max `stall` (blocks) | 40 | 40 | 42 | 41 |

against `DEGRADED_MODE_LAG_BLOCKS = 16`. A stall of 16 is two missed checkpoints, and two-in-a-row happens about a sixth of the time.

**Whether 16 is mis-set or the committee genuinely wobbles under real RTT cannot be answered from this run**, and the reason is worth stating plainly: **a node emits nothing when it misses a checkpoint.** Across the full 48 h node0 produced *ten* non-telemetry log lines, all at startup. No round number, no vote count, no timeout reason, no absentee list. The `stall` counter climbs from 8 to 40 and falls back, and the interval between is opaque.

That gap is [issue #87](https://github.com/qumbra-labs/qumbra-lab/issues/87). It is not cosmetic — it blocks a FROZEN-set decision, and `DEGRADED_MODE_LAG_BLOCKS` must not be touched until it is closed.

### A cross-check that did hold

`regime = Degraded` and `stall > 16` agree on **14,647 of 14,659** archived samples across all four nodes. The twelve exceptions are all the same thing: the **genesis head** — `tip=0`, `final=-`, nothing finalized yet — three samples per node inside the run's first 60 seconds. That is [issue #73](https://github.com/qumbra-labs/qumbra-lab/issues/73), and this run quantifies it. **After the first finalization there are zero disagreements.**

### Cross-node finality agreement — what is and is not provable here

The four nodes end at the same `final` (2352), and no node's `final` ever decreased. Between those two facts they do drift apart momentarily: aligned on a 30 s grid, the four disagree on `final` height in **184 separate intervals**, all of which **resolve back to exact agreement** — median 60 s, p90 150 s, max 330 s, and the largest disagreement is **40 blocks, which is exactly the largest single finality advance observed**.

That is the signature of sampling phase against jump-wise advance, not of divergence: telemetry is emitted every ~47 s per node with independent phase, finality moves in steps of 8–40 blocks, so two nodes sampled a cadence apart will straddle a step. Tip spread behaves the same way — greater than 3 blocks on 4.9 % of aligned samples, maximum 8.

**The honest limit: telemetry carries no checkpoint identity**, so this pack can show that no node's finality height regressed and that the four always reconverge — it **cannot** show that the four finalized the *same* checkpoints. Height agreement is not identity agreement. That is [issue #84](https://github.com/qumbra-labs/qumbra-lab/issues/84), and it is a limitation of the evidence surface, not a finding about the net.

## Observation gaps — disclosed, and why they cost nothing

The 5-minute sampler did **not** cover the run continuously. Two gaps, both operator-side:

| window (+0800) | duration | cause |
|---|---|---|
| 2026-07-27 08:39:45 → 18:48:46 | **10.15 h** | the operator's egress IP rotated; the SSH security-group rule admitted one stale `/32`. Port 22 is the only ingress open to the operator, so this was total, instant blindness. The window matches a workday. |
| 2026-07-28 06:51:59 → 09:48:52 | **2.95 h** | sampler process died with an editor restart, then hit the same stale-CIDR problem |

Roughly **13 of the sampled run's ~48 hours were unobserved by the sampler** — about 27 %.

**Both windows were recovered line-by-line from the nodes' own logs.** For the 10.15 h window: 785 telemetry lines, none missing, tip 862 → 1353, finality 856 → 1344, 18 % `Degraded` — statistically indistinguishable from the 15.9 % measured across the whole run. Nothing happened in the dark.

State it that way when quoting this pack: **the record is complete; the live view was not.**

The fix and the lessons are recorded in `qumbra-deploy/OPERATOR.md` §3/§6: `admin_cidrs` is a list now (add addresses, never swap them), and *four hosts on three continents do not fail simultaneously — when they appear to, suspect the one path they share.*

## What this run does NOT claim

- **The four scenario drills are not in this pack**: late-joiner sync, mining-node restart, 2+2 partition → heal, committee stall → recovery. They are owed and they are **deliberately not run yet**.
- **The reason is the image, not the schedule.** These hosts carry an image built 2026-07-26. Merged to `main` since: [#79](https://github.com/qumbra-labs/qumbra-lab/pull/79) (block bodies bound to their header — a *consensus-correctness* fix), [#82](https://github.com/qumbra-labs/qumbra-lab/pull/82) (D3 leaf-digest binding), [#86](https://github.com/qumbra-labs/qumbra-lab/pull/86) (M11 peer discovery). Drills validate the design *as it stands*, so drill evidence taken on this image would describe a superseded build and would have to be re-run.
- **The continuity claim is unaffected by that, and the distinction matters.** "A real build ran unattended for ≥ 48 h with zero restarts and zero finality reversions" does not weaken when the build advances. Drills that validate present design do not have that property.
- **One of the four is not runnable today at all** — committee stall → recovery, for the reason in the finality section: the node is silent on exactly the quantity being measured.
- No claim is made about NAT'd or adversarial participants; every host here is one we control, with a public IP and an open inbound P2P port.
- `dialable=<n>/<known>` does **not** appear in this run's telemetry: M11 discovery merged after the image was built.

Sequencing decided 2026-07-28 (`observability-and-evidence.md` §5.1, `OPERATOR.md` §4): **seal this pack → build #87 → one redeploy carrying #79 + #82 + #86 + #87 → then all four drills.**

## Artifacts

| file | what it is |
|---|---|
| `qumbra-ops/node{0..3}-telemetry-full.log` | **the primary record** — each node's complete `docker logs -t` telemetry, `tip=0` onward |
| `docs/m10-t03-phase-b-wan-soak.log` | the 5-minute sampler log (2,672 lines), with both gaps present exactly as recorded — not cleaned |
| this doc + `-zh` | the pack |

## Owed after this pack

- [#87](https://github.com/qumbra-labs/qumbra-lab/issues/87) — committee round diagnostics + structured metrics; blocks the `DEGRADED_MODE_LAG_BLOCKS` question.
- The four drills, on the post-redeploy image.
- `testnet-plan` M10/M11 estimate-vs-actual; the ROADMAP M10 row.
- [#73](https://github.com/qumbra-labs/qumbra-lab/issues/73) — genesis-head telemetry, now quantified above at exactly 3 samples per node.
