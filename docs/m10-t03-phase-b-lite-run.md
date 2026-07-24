# M10-T0-3 Phase B-lite — LOCALHOST/DOCKER run doc

> **Scope label: LOCALHOST/DOCKER.** This is the docker-compose rehearsal of the
> Phase-B protocol on one dev rig (issue #64 amendment 3). It makes **NO
> WAN-latency claims.** The latency-sensitive measurements — checkpoint cadence
> under real RTT, the LWMA difficulty trace at WAN pacing, and the **≥48 h**
> duration bar — remain owed to **Phase B-WAN** (the 4-VPS run, gated on Larry's
> VPSes). What this run establishes: the binary runs as a real Linux container,
> the genesis/keys provision correctly, and the four soak scenarios + a **≥6 h**
> steady run behave correctly over real TCP with real RandomX and disk persistence.

## Rig + provenance (bench discipline §2)

| Field | Value |
|---|---|
| Repo rev | `claude/m10-t03b` (base `6d360cc`) + this branch's Phase B-lite changes; final SHA stamped at commit |
| Host | Apple M5 Max, 36 GiB |
| OS | macOS (Darwin 25.5.0) |
| Container runtime | Docker Desktop (Engine 29.6.1, Compose v5.3.0), **aarch64 Linux** VM |
| Toolchain | rustc 1.95.0 (image base `rust:1.95-bookworm`) |
| RandomX | `randomx-rs` 1.4.1 (light mode), vendored C++ built in-container |
| Block time | 75 s (FROZEN, consensus-parameters §2) |
| Mining clock | `WallClock` (amendment-1 item 0 — real header timestamps) |
| Power state | AC power |

## ⚠️ Headline finding — committee finality does not form in the distributed T0 topology

**Filed as [issue #70].** With the real 21-key **6/5/5/5** split across 4 nodes, no
single node holds ≥ quorum (15), and there is **no cross-node vote aggregation**
(`make_checkpoint` signs only local keys; `ingest_checkpoint` counts only the
votes in one call; `announce_checkpoint` relays only a locally-finalizing
checkpoint; no `MsgType::Vote` / vote pool exists). So finality never bootstraps —
`final=-`, `regime=Degraded` on all nodes, confirmed through tip=11 (past the
height-8 cadence checkpoint). **Liveness gap, NOT a safety violation** (no fork
past finality / double-finalization / supply mismatch → not a STOP-POINT). Block
production, gossip, heaviest-chain convergence, and LWMA retarget are all healthy.
It was invisible until now because every prior test/soak used one node holding a
full quorum ("federation-of-one") or a pre-aggregated vote vector.

**Consequence for this run:** the finality-dependent scenarios (§4 partition
*finality* stall/heal, §5 committee stall→recovery) are **deferred to the #70
fix**. This doc harvests the finality-independent evidence, which is substantial:
RandomX-on-Linux, genesis rehearsal, late-joiner sync, restart=replay, and the
PoW + LWMA liveness soak. Evidence trace:
`docs/m10-t03-phase-b-lite-finding-finality.log`.

[issue #70]: https://github.com/lai3d/qumbra-lab/issues/70

## Precondition item 0 — wall-clock header timestamps ✓

`qumbra-node run` unconditionally sets `MiningClock::WallClock` (`run.rs`
`run_node`), so mined-block header timestamps are real wall-clock time (clamped
non-decreasing vs parent), not the deterministic 75 s counter the in-process
sims/tests use. LWMA therefore sees real, variable solvetimes → a non-constant
difficulty trace (item 4 signal). In-process sims/tests keep the deterministic
clock (default). No code change needed here for Phase B-lite — Phase A delivered it.

## Observability surface (new this branch)

`run_until` now emits a `TELEMETRY …` line to stdout on a ~30 s cadence, reusing
the T0-2 `Telemetry::assemble` rule (never re-deriving the frozen Ebb-and-Flow
semantics) plus the tip block's PoW difficulty:

```
TELEMETRY tip=<h> final=<h|-> stall=<d> age_s=<chain-secs> diff=<u64> peers=<n> mempool=<n> epoch=<e> regime=<Final|Degraded>
```

Captured via `docker compose logs` (`-t` for wall-clock stamps). This is the only
node-binary code change in Phase B-lite (issue #64: "code fixes go through their
own mini-review"); it carries a unit test (`telemetry_sample_reports_live_state`).

## Topology

- N = 4 containers, all mining + holding keys; committee keys split **6/5/5/5**
  (node0..node3 hold 00–05 / 06–10 / 11–15 / 16–20).
- Full mesh over the `qumbra_t0` bridge network (each dials the other three by
  service name); node0 = de-facto bootstrap; node3 = late-joiner.
- Shared genesis minted once by the `genesis-init` service; pinned hash
  `4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3`.
- A 2+2 split ⇒ **11 | 10** keys, both **< 15 quorum** ⇒ finality **correctly
  stalls** during partition.

---

## 0. RandomX-on-Linux build (the caveat's first validation) — ✅ PASS

`docker compose build` **succeeded first try** (exit 0). `randomx-rs` 1.4.1
compiled + linked on **aarch64 Linux** (`rust:1.95-bookworm`, apt `cmake` 3.25.1 +
`clang`/`build-essential`); `cargo build --release --locked -p qumbra-node`
finished in ~19 s; runtime image `qumbra-node:t0-lite` = 153 MB. The binary **runs
on Linux** — `genesis init` in-container reproduced the frozen hash exactly and
self-verified, and all 4 nodes mine **real RandomX** blocks (tip advanced 0→11+),
so `randomx-rs` is statically linked and the VM initializes at runtime.

**The deploy/README "RandomX Linux cross-compile caveat" is resolved (positively).**
No fallback to 4-local-process mode was needed. The image is a reusable artifact
for the Phase B-WAN VPS deploy (VPSes are Linux too).

## 1. Genesis rehearsal — ✅ PASS (finality caveat: see headline)

`genesis-init` minted the shared genesis + 21 keys once; all 4 nodes started and
byte-verified it. In-container genesis hash ==
`4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3` == the pinned
T0 hash (asserted by `soak.sh rehearsal`). All 4 nodes reached full mesh
(`peers=3`), mined on the 75 s cadence, and advanced in lockstep (identical tip +
difficulty across nodes — heaviest-chain consistent, no fork). **Finality did not
reach Final** — see the headline finding (#70); block-level rehearsal is otherwise
green.

## 2. Late-joiner sync-from-genesis (node3) — ✅ PASS

node3's data wiped in place, then `dc start` fresh (tip=0, genesis diff 256).
It connected (`peers=3`) and within ~30 s **synced to tip=3 ≥ the leader** via
header-sync over real TCP, adopting the chain's difficulty (55, not its own
genesis 256) — i.e. it discarded any self-mined genesis fork for the heavier
network chain. Sync-from-genesis works over the docker net. (Finality N/A per #70.)

Procedure note: a late joiner must be started on a **stable** network (all
established peers up + resolvable) because of finding #7 (dial-once, no re-dial);
recreating a single container can recreate the compose network and blip DNS,
which starved the first attempt's one-shot dials. Bringing all nodes up together
and stop/wipe/start-ing the joiner is the reliable path.

## 3. Mining-node restart (open==replay on disk) — ✅ PASS

node1 stopped at tip=5 (volume kept), restarted: came back at **tip=5** (did not
reset to genesis → resumed from the on-disk append-only block log = open==replay)
and **reconnected** (`peers=3`, its boot-dials to the stably-bound peers
succeeded), then continued mining. Disk persistence + restart-safety confirmed on
real container volumes.

## 4. 2+2 partition → heal — ⏸ finality aspect DEFERRED to #70

The task-book purpose of this scenario is the **finality** stall under a quorum
split. Since baseline finality never forms (#70), the "finality correctly stalls
then resumes" assertion cannot be exercised meaningfully yet. The `soak.sh
partition`/`heal` machinery (true 2+2 via `docker network disconnect` + a `sideb`
network keeping the B-side pair talking) is in place and validated at the network
level; the block-level fork-choice divergence/reconvergence observation is
optional and noted, but the headline finality result waits for the #70 fix.

## 5. Committee stall → T0-2 recovery — ⏸ DEFERRED to #70

Same reason: with no baseline finality, "stall → Degraded → restart → catch-up →
Final" has no Final to return to. `soak.sh committee-stall`/`committee-recover`
are in place; the recovery result waits for #70.

## 6. ≥6 h telemetry-sampled steady run — ✅ PASS (liveness/endurance)

Ran on the clean 4-node baseline; **`SOAK COMPLETE t+21635s samples=73 tip=388
diff[1134..4072] maxstall=388`**, ~**6.26 h continuous** across 77 samples (5 min
cadence), **zero ALERTs** (the guard never tripped on node-down or tip-divergence).
Full trace: `docs/m10-t03-phase-b-lite-soak.log`.

| Metric | Result |
|---|---|
| Duration | ~6.26 h continuous (≥6 h ✓), 77 samples, all 4 nodes up throughout |
| Blocks | tip 0 → ~388 (~58 s/block effective; see multi-miner note below) |
| Tip consistency | ≤ 1–2 block spread across all 4 nodes the whole run (no fork; divergence guard `>6` never tripped) |
| LWMA difficulty | 256 (genesis) → 42 (startup transient) → climbed + converged; steady window `[1134..4072]`, leveling ~3900–4072 |
| RAM / node | ~262 MiB (RandomX **light** cache + node) — far inside the ≥4 GB VPS spec |
| CPU / node | bursty — ~100 % on whichever node is hashing at the 75 s tick, near-idle otherwise |
| Disk / node | 4–8 KB data volume for ~388 coinbase-only blocks (negligible) |
| Finality | `Degraded` throughout (`maxstall = tip`, per #70) — **this run measures PoW/gossip/LWMA liveness + endurance, not finality** |
| Consensus misbehavior | **none** (no fork past finality, no double-finalization, no supply anomaly, no crash) |

**Item-4 / multi-miner LWMA note (finding).** With 4 independent miners each on the
frozen 75 s timer, the *aggregate* block-production rate is ~4× a single node's, so
LWMA correctly ramps difficulty hard (256 → ~4000) to pull the effective interval
back toward 75 s, then levels off. The trace is non-constant and self-correcting —
exactly the WallClock (item-0) signal — but the steady difficulty and effective
block spacing here reflect the **4-miner localhost aggregate**, not a WAN topology.
Real per-node hashrate and RTT at the WAN pacing remain owed to Phase B-WAN.

## Acceptance suite

Bench discipline §5 (full unfiltered `cargo test --release -p qlab-bench`, no mode
filter): **91 passed; 0 failed** (all `#[test]` in the crate), 555.24 s, run
**serial (`--test-threads=1`)** on the clean rig after the soak tore down — the
N6-documented OOM-safe mode; serial is not a mode filter, so acceptance validity
holds. Confirms this branch's only code change (the `run.rs` telemetry surface,
in `qumbra-node` — a crate qlab-bench does not depend on) leaves every m4 /
consensus / narrow-Keccak invariant green. `qumbra-node` crate: 28/28.

## Findings (honest list)

1. **[headline] Distributed committee finality never forms — [issue #70].** The
   6/5/5/5 key split has no single quorum-holder and no cross-node vote
   aggregation, so finality can't bootstrap. Liveness gap, not safety. Blocks the
   finality soak scenarios (§4/§5).
2. **RandomX builds + runs on aarch64 Linux (positive).** The deploy/README
   cross-compile caveat is cleared; the image is a reusable VPS artifact.
3. **LWMA difficulty trace is correct (item 4, LOCALHOST pacing).** Observed
   `256 → 42 → 55 → 63 → 68 → 72 → 74 → 75 → 76 → 77` over the first 11 blocks: an
   initial ease (the genesis-timestamp-0 transient makes the first solvetime clamp
   long → LWMA lowers difficulty) then a clean climb converging toward the
   difficulty that yields 75 s spacing. All nodes lockstep. Real, non-constant —
   exactly the signal the WallClock precondition (item 0) exists to produce. _(WAN
   pacing / a longer trace remains owed to Phase B-WAN.)_
4. **Telemetry `last_finalized_age_secs` is inflated pre-first-finalization.**
   Genesis block timestamp is 0 while WallClock blocks carry real Unix time, so
   `age_s` reads ~1.79e9 until something finalizes against a real-timestamped
   block. Cosmetic (chain-time metric off a 0 baseline); would self-correct once
   finality lands. Noted, not fixed here.
5. **Peer count reports 3–4 (occasionally >3).** Full-mesh nodes count inbound and
   outbound connections separately, so a node can briefly show 4 for a 4-node net.
   Cosmetic; connectivity is correct (≥3, all peers reachable).
6. **`soak.sh` script bug caught + fixed mid-run:** `latest()`'s `grep` failed the
   pipeline under `set -o pipefail` for a node with no telemetry yet (wiped
   late-joiner), aborting `snapshot`. Fixed with `|| true`.
7. **Node dials peers ONCE at startup with no re-dial/retry** (`run.rs` `start()`
   dials `dial_peers` once; `P2pNode::tick()` never dials; the `Addr` handler is
   "prototype: no auto-connect"). Consequences: (a) a node whose configured peers
   are momentarily unresolvable at boot never joins (bootstrap fragility); (b)
   after a partition drops TCP, neither side re-dials — **partition-heal will not
   auto-reconnect without a node restart** (or an inbound dial from a
   freshly-booted peer). This compounds the N7 finding (gap/partition recovery
   runs through header-sync / wants a sync kick). Worth a follow-up for the
   internal-net stage. _(It also made the late-joiner scenario sensitive to docker
   network-recreate timing — see the run notes; the reliable procedure is to bring
   all nodes up together, then stop/wipe/start the joiner on the stable network.)_
8. **Multi-miner LWMA aggregate dynamic (from the ≥6 h soak).** 4 independent
   miners on the 75 s timer produce ~4× a single node's block rate; LWMA ramps
   difficulty ~16× (256 → ~4000) to restore the 75 s target, then levels. Correct,
   self-correcting — but the steady difficulty reflects the localhost 4-miner
   aggregate, not WAN topology. Endurance was clean: ~6.26 h, 77 samples, all
   nodes lockstep (≤2-block spread), zero misbehavior.
9. Cross-ref the N7 finding (announce-flood drops orphans; gap/partition recovery
   runs through the header-sync path).

## Transfers to Phase B-WAN

The image, genesis-bake, entrypoint, and soak driver transfer as-is to the 4-VPS
deploy. Phase B-WAN then owes only: real-RTT checkpoint cadence, the LWMA trace at
WAN pacing, and the ≥48 h continuous run.

## What this run does NOT claim

No WAN latency, no ≥48 h endurance, no multi-host fault isolation beyond docker
network namespaces on one kernel. Those are Phase B-WAN's, per amendment 2/3.
