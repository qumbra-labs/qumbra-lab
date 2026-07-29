# Qumbra T0 internal-net — Phase B-lite (docker/localhost)

The **docker-compose rehearsal** of the M10-T0-3 Phase-B protocol (issue #64
amendment 3). Four real `qumbra-node` containers on a real TCP bridge network,
**real RandomX light**, **wall-clock** header timestamps, the **frozen 75 s**
block time, and **distinct on-disk data-dir volumes** — the full soak without
waiting on the 4 VPSes.

> **LOCALHOST/DOCKER.** The bridge is loopback-fast (sub-millisecond RTT) unless
> you inject delay — see [Latency injection](#latency-injection-soaksh-netem)
> below. A run with no `netem` is a **zero-latency** run and its numbers are not
> WAN numbers; a run with `netem` is an **emulated uniform symmetric delay** and
> must be stated as such, never as "WAN". Everything reusable here — the image,
> the genesis-bake, the scenario driver — transfers to the VPS deploy (VPSes are
> Linux too).

## Why docker (over 4 bare local processes)

1. **True partition.** Each container has its own network namespace, so the 2+2
   split is a real `docker network disconnect`, not "stop two processes" —
   faithful to the Crosslink-class partition-period finality behavior we test.
2. **First Linux build of RandomX.** `deploy/README.md` flags the *RandomX Linux
   cross-compile caveat* (a macOS binary won't run on a Linux VPS; `randomx-rs`
   had never been built on Linux in this project). The container **is** Linux, so
   this is that caveat's first real validation — and the image is a reusable VPS
   artifact.
3. **See it run.** `docker compose up` and watch 4 nodes produce blocks,
   finalize, and emit telemetry.

## RIG DISCIPLINE (non-negotiable)

Do **not** `docker compose build`/`up` (or `soak.sh rehearsal`) while the b4 bench
is running. 4 RandomX light caches (~256 MiB each) on the Docker-Desktop Linux VM,
on top of the ~30 GB bench, will OOM. Check first:

```sh
pgrep -f qlab_bench     # must print nothing
```

`soak.sh` refuses to build/up while it matches.

## Layout

- **`Dockerfile`** — multi-stage: `rust:1.95-bookworm` builder (cmake + clang for
  `randomx-rs`) → `debian:bookworm-slim` runtime with the binary + `entrypoint.sh`.
- **`entrypoint.sh`** — `init` mints the shared genesis + 21 keys once; `run <idx>`
  generates node *idx*'s config (its key slice of the 6/5/5/5 split, full-mesh dial
  peers, pinned genesis hash) and runs it.
- **`docker-compose.yml`** — a one-shot `genesis-init` + 4 node services; shared
  genesis volume + per-node data volumes; two networks (`qumbra_t0`, and
  `qumbra_t0_sideb` used only during a 2+2 partition).
- **`soak.sh`** — the scenario driver (below).

## Topology

- **N = 4**, all mining, all holding keys. Committee keys **6/5/5/5** across
  node0..node3. A 2+2 split leaves **11 | 10** keys — both **< 15 quorum**, so
  finality **correctly stalls** during the partition (that is the test, not a bug).
- **Full mesh**: each node dials the other three by compose service name. node0 is
  the de-facto bootstrap; node3 is the late-joiner in the sync scenario.
- Genesis pinned to the frozen T0 hash
  `4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3`; every node
  byte-verifies it on startup (`expected_genesis_hash`).

## Observability

`qumbra-node run` emits a `TELEMETRY …` line to stdout on a ~30 s cadence (tip,
finalized, stall depth, chain-time age, tip difficulty, peers, mempool, epoch,
finality regime — reusing the T0-2 `Telemetry` rule). Read it with:

```sh
docker compose -f deploy/docker/docker-compose.yml logs -t -f node0   # wall-stamped
deploy/docker/soak.sh status                                          # one snapshot/node
deploy/docker/soak.sh sample 3600 60                                  # sample for an hour
```

## Running the protocol

```sh
deploy/docker/soak.sh rehearsal          # build + assert genesis + start 4 nodes
deploy/docker/soak.sh sample 300          # watch them mine & finalize on the cadence
deploy/docker/soak.sh latejoiner          # node3 joins late → sync-from-genesis
deploy/docker/soak.sh restart node1       # open==replay on node1's volume
deploy/docker/soak.sh partition           # true 2+2 split → finality stalls both sides
deploy/docker/soak.sh heal                # reconnect → converge + finality resumes
deploy/docker/soak.sh committee-stall     # stop 3 key-holders → Degraded
deploy/docker/soak.sh committee-recover   # restart → T0-2 catch-up → Final
# … then a ≥6 h telemetry-sampled steady run …
deploy/docker/soak.sh teardown            # down -v
```

**STOP-POINT:** any consensus misbehavior (fork past finality, supply mismatch,
double-finalization) ⇒ stop, preserve state (`docker compose logs`, the volumes),
report — never patch-and-continue.

## Latency injection (`soak.sh netem`)

Added for [#107](https://github.com/lai3d/qumbra-lab/issues/107) step 1b, where a
loop-period regression visible on the WAN net did not reproduce locally and
**latency was the only remaining difference** — a question this harness could not
express. Run these against a net that is already up; no restart is needed.

```sh
deploy/docker/soak.sh netem 100        # 100 ms one-way on every node → ~200 ms RTT
deploy/docker/soak.sh netem 100 20     # …with 20 ms normal-distributed jitter
deploy/docker/soak.sh netem-show       # what is installed + the measured RTT matrix
deploy/docker/soak.sh netem-clear      # remove it, and prove it is gone
```

**The argument is ONE-WAY delay, not RTT.** `tc netem delay` delays egress, and
every node carries the same qdisc, so a packet and its reply each pay it once:
**RTT ≈ 2 × delay**. To model the T0 WAN's measured **68–223 ms RTT** baseline,
use `netem 35` and `netem 110`, not `netem 68` and `netem 223`. Every command
prints both figures so the factor of two never has to be remembered.

**Both checks run, and the second is the one that matters.** `netem` asserts the
qdisc is installed at the requested delay on every node (`tc qdisc show`, printed
verbatim, `die` on any mismatch) **and then measures ICMP RTT across all twelve
ordered pairs**. The qdisc check alone is not enough: a qdisc on the wrong device
— or on a device the container's traffic does not leave by — reads green and
changes nothing, and a soak under a silently-inert netem produces a clean,
confident answer that means nothing at all.

Requires `cap_add: [NET_ADMIN]` (docker-compose.yml) and `iproute2` +
`iputils-ping` in the runtime image (Dockerfile). A net brought up from an image
built before those landed will fail loudly at `tc`, not silently.

**What a netem run is and is not.** It is an emulated, **uniform, symmetric**
delay with no loss and no reordering. The real T0 WAN is per-pair, asymmetric,
jittery and lossy, on `t4g.small` Graviton VMs rather than containers sharing one
machine. So netem answers *"is this effect latency-shaped?"* — a negative result
rules out delay-as-such; it does **not** rule out the WAN.

## Fallback (if RandomX won't build on Linux)

If `docker compose build` fails at the `randomx-rs` compile/link step, that is a
**Phase B-lite finding**, not a task failure (it is exactly the documented caveat).
Report it, file the Linux-build issue, and run the soak via the **4-local-process
mode** on the dev rig instead — `deploy/deploy.sh --hosts` in local mode lays down
4 node dirs (see `deploy/README.md`); drive the same scenarios with process
stop/start (partition becomes "stop two processes", a documented lower-fidelity
substitute for `docker network disconnect`).
