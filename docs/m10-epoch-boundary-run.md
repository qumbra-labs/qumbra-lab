# Local epoch-boundary soak — LOCALHOST/DOCKER run doc

> **Scope label: LOCALHOST/DOCKER. No WAN-latency claims.** This run exists to cross one specific line — the **1,152-block committee epoch boundary** — with every other variable held as still as possible. The WAN measurements (real RTT, LWMA at WAN pacing, ≥ 48 h) belong to Phase B-WAN ([#64](https://github.com/lai3d/qumbra-lab/issues/64)) and are not claimed here.

> **⚠️ Provenance caveat, stated first because it is the weakest thing about this run.** This soak was started, sampled and is being written up **by the coordinator** — the same role that will rule on it. That is exactly the independence problem `qumbra-deploy/OPERATOR.md` R1 exists to prevent for T-ops. It was started at 00:24 on 2026-07-26, before the T-ops role existed, and it was not migrated afterwards. **Read its conclusions as coordinator-produced, not independently verified.** The Phase B-WAN run does not share this defect.

## Why this run exists

The committee epoch is **1,152 blocks** (`EPOCH_LENGTH_BLOCKS`, FROZEN v1.0). At the boundary the epoch machinery does real work: staged membership changes apply, the roster is resealed for the new epoch, per-epoch history is retained so late checkpoints verify against the right committee, and the downtime-jail window resets.

**No live multi-node net had ever crossed one.** Every prior exercise of that machinery was a unit test or an in-process simulation with an accelerated `SIM_EPOCH_LENGTH_BLOCKS`; the real 1,152 boundary had never been reached by a running net — Phase B-lite stopped at tip 388, the T0-5 docker soak at 245.

Two things made it worth doing on localhost rather than waiting for the WAN run to cross the same line ~24 h in:

1. **Isolation.** On WAN, an anomaly at the boundary could be the epoch machinery or the network. Here it can only be the machinery.
2. **Debugging locality.** A defect found here is one `docker exec` away; the same defect found 24 h into a four-continent run is not.

**Its cost is stated in the coordinator playbook and is not small**: it occupied the dev rig for ~22 h while three completed batons queued behind it. That trade was correct at 00:24, defensible at 14:00, and should have been recomputed at 17:00 when the queue deepened — recorded there as *mispriced, not wasted*.

## Rig and setup

| Field | Value |
|---|---|
| Topology | 4 nodes, docker-compose (`deploy/docker/`), the Phase B-lite image |
| Committee | 21 keys split **6/5/5/5** — no node holds the quorum of 15 |
| PoW | RandomX **light**, real |
| Block time | 75 s (FROZEN), `WallClock` mining clock |
| Genesis difficulty | 256 (`[devnet-placeholder]`, deliberately low) |
| Host | Apple M5 Max, 36 GiB, AC power |
| Started | 2026-07-26 00:24:00 +0800 |
| Sampler | 5-minute interval, reads the raw `TELEMETRY` line from each node's container log |

`soak.sh status` was **not** used for sampling: its condensed output omits the `epoch` field, which is the one this run exists to watch.

### STOP-checks armed every sample

- finality **regressing** on any node;
- the four nodes reporting **different `epoch` values** (a split roster view);
- a node going silent;
- and the crossing itself, logged when any node reports `epoch ≥ 1`.

## Observations to 22:20 (264 samples, tip 1146 / 1152)

**Zero alerts. No STOP-check has fired at any sample.**

### Difficulty converged, and that is what moved everything else

`diff` climbed 256 → ~3,200–3,700 and then oscillated there. That is LWMA doing its job: genesis difficulty is deliberately far below the 75 s target, so early blocks arrived in seconds and the algorithm spent the first hours correcting.

### Finality holds, then jumps — bounded, not runaway

`stall` (= tip − final) distribution across the run:

| stall | samples |
|---|---|
| 1–8 | 146 |
| 9–16 | 76 |
| 17–24 | 30 |
| 26–33 | 4 |

Maximum observed **33**. The shape is oscillation, not drift: stall climbs into the teens or twenties, one finality advance lands, and it drops back to single digits. `regime` was `Final` on **226 of 264** samples; the 38 `Degraded` readings are all `stall > 16`, which is `DEGRADED_MODE_LAG_BLOCKS = 2 × cadence`, **while `final` continued to advance**.

**This matters beyond this run.** T-ops reported the same hold-then-jump pattern on the WAN net and asked whether it was a WAN effect. It is not: it appears here, on localhost, with sub-millisecond RTT. The mechanism is in the protocol, not the network — several checkpoint slots accumulate votes concurrently (`try_checkpoint` proposes every pending grid height in one pass), whichever crosses quorum first finalizes, and lower slots then die by `NotAdvancing`. Nothing is lost, because `set_finalized` requires the new head to descend from the old one: **the finalized head is a high-water mark, so finalizing 1120 finalizes everything below it.** WAN widens the race; it does not create it.

### What is still owed by this run

- **the crossing itself** — at tip 1152, ~6 blocks away at the time of writing;
- confirmation that all four nodes advance `epoch` **identically** across it;
- whether finality survives the boundary — note the run is entering it **while finality is held** (`final=1120`, stall 26), which is more informative than a quiet crossing: the roster reseal and the vote accumulation overlap, which is where a boundary-timing defect would show.

The sampler stops at tip ≥ 1200, so roughly 48 blocks of post-boundary behaviour will be recorded rather than stopping at the line.

## Evidence

`~/qumbra-ops/`-style raw log for this run lives in the coordinator session's scratchpad as `epoch-soak.log` (264 samples, four nodes each). It is committed with this doc when the run ends.
