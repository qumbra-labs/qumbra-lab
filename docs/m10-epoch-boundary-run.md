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

`stall` (= tip − final) distribution across the run — **node0's reading at each of the run's 277 samples**:

| stall | samples |
|---|---|
| 1–8 | 155 |
| 9–16 | 83 |
| 17–24 | 35 |
| 26–33 | 4 |

> **Corrected twice, 2026-07-28 — and the second correction is the instructive one.** The original table read 146/76/30/4 (sum 256) and was simply wrong: no node, no prefix and no four-node total produces it. The first fix read 146/80/34/4 (sum 264) — internally consistent, and consistent with the "38 `Degraded`" figure it cited as corroboration, because **both were counted over the run's first 264 samples rather than all 277**. A recount over the whole committed `m10-epoch-boundary-soak.log` gives the table above; 264 is the *only* prefix length that reproduces the intermediate values, which is what identified the scope error. `stall` never reads 0 or 25, so the buckets lose nothing.
>
> The general lesson, the same one that nearly charged D3 with B″'s +51 KB: **a number carries its counting basis, and the basis does not grow when the data does.** State the basis next to the number — that is why this table now says "277 samples" in its own caption.

Maximum observed **33**. The shape is oscillation, not drift: stall climbs into the teens or twenties, one finality advance lands, and it drops back to single digits. `regime` was `Final` on **238 of 277** samples, and the **39** `Degraded` readings are **exactly** the samples with `stall > 16` — `DEGRADED_MODE_LAG_BLOCKS = 2 × cadence`. Checked both directions across all 277: **zero samples disagree**, so on this run the reported regime is not merely consistent with the threshold, it is a faithful function of it. And `final` kept advancing throughout.

**This matters beyond this run.** T-ops reported the same hold-then-jump pattern on the WAN net and asked whether it was a WAN effect. It is not: it appears here, on localhost, with sub-millisecond RTT. The mechanism is in the protocol, not the network — several checkpoint slots accumulate votes concurrently (`try_checkpoint` proposes every pending grid height in one pass), whichever crosses quorum first finalizes, and lower slots then die by `NotAdvancing`. Nothing is lost, because `set_finalized` requires the new head to descend from the old one: **the finalized head is a high-water mark, so finalizing 1120 finalizes everything below it.** WAN widens the race; it does not create it.

## 🎯 The crossing — 2026-07-26 22:29:27 +0800, sample 266

**The 1,152-block committee epoch boundary was crossed, and no live multi-node net had done it before.**

```
node0  tip=1155  final=1144  stall=11  diff=3244  epoch=1  regime=Final
node1  tip=1155  final=1144  stall=11  diff=3244  epoch=1  regime=Final
node2  tip=1154  final=1144  stall=10  diff=3230  epoch=1  regime=Final
node3  tip=1154  final=1144  stall=10  diff=3230  epoch=1  regime=Final
```

**All four checks pass:**

1. **All four nodes reported `epoch=1` at the same sample.** The transition completed within one 5-minute sampling interval (the sampler cannot resolve ordering inside it), and no sample at any point showed a split roster view — that was one of the armed STOP-checks, and it did not fire.
2. **Finality survived the boundary.** `final=1144` on all four, `regime=Final`, and `final` continued to advance after the line.
3. **Zero alerts across the whole run** — no STOP-check triggered at any sample (277 by run end).
4. **The crossing was not quiet, which is the useful part.** Two samples earlier the net was at `final=1120, stall=24–26` — finality had been held for ~35 minutes. It then advanced to 1144 and crossed the boundary at stall 10–11. **So the roster reseal happened in the same window as an active vote accumulation and did not disturb it.** Had the run entered the boundary during a quiet stretch, that overlap would not have been exercised at all.

That last point was predicted in this document before the crossing, and it is the reason the run is worth more than a green tick: a boundary-timing defect would show precisely where reseal and accumulation overlap, and that is the case that got tested.

### Post-boundary behaviour — recorded, and the run is complete

The sampler ran on to **tip 1201** and stopped itself at 23:24:28, **277 samples, zero alerts across the whole run**. `epoch=1` held on all four nodes for the twelve samples after the crossing, and finality kept advancing through them — final state `tip=1201 final=1192 stall=9 regime=Final`, identical on all four.

Notably `stall` was **lower** after the boundary than before it (single digits, against the 24–26 the net carried into the crossing). The reseal did not leave finality worse off.

## Evidence

`docs/m10-epoch-boundary-soak.log` — the complete sampler record, 277 samples × four nodes, committed with this doc.
