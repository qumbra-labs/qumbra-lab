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

## Building the image (revision provenance)

The runtime stage stamps `org.opencontainers.image.revision` from a build-arg
(`GIT_REVISION`). That key is the one the operator provenance check already reads;
leaving it off the command line used to produce an image whose inspect returned
empty (the first `t0-wan-7` build, 2026-08-02 — issue #224). The Dockerfile
defaults the arg to the string `unknown` so a forgotten flag is visible rather
than empty.

```sh
# From the repo root. Pass the revision; tag as you need.
docker build \
  -f deploy/docker/Dockerfile \
  --build-arg GIT_REVISION=$(git rev-parse HEAD) \
  -t ghcr.io/lai3d/qumbra-node:<tag> \
  .

# Read it back — this is the check, not the build's exit code.
docker image inspect ghcr.io/lai3d/qumbra-node:<tag> \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}'
```

A build that omits `--build-arg GIT_REVISION=…` still succeeds, and inspect then
returns `unknown`. That is deliberate: an empty label is ambiguous; `unknown`
means nobody passed a revision.

## Topology

- **N = 4**, all mining, all holding keys. Committee keys **6/5/5/5** across
  node0..node3. A 2+2 split leaves **11 | 10** keys — both **< 15 quorum**, so
  finality **correctly stalls** during the partition (that is the test, not a bug).
- **Full mesh**: each node dials the other three by compose service name. node0 is
  the de-facto bootstrap; node3 is the late-joiner in the sync scenario.
- Genesis pinned to
  `bd3604804aade38ece989d87e72e3541cede939512f513840c5cdcf13986a66f`; every node
  byte-verifies it on startup (`expected_genesis_hash`).
  **This value has moved twice**, and it is what *this tree* builds, not what any
  host runs: issue #101 (the genesis file embeds the genesis block, which gained
  `coinbase_rkm` — `4a75b3b8…c2c3` → `8811d4e0…3cff`) and issue #115 (the genesis
  header now commits to its own body, taken deliberately at the mint —
  `8811d4e0…3cff` → the value above). The live T0 net is still pinned to the
  pre-#101 `4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3`; a
  binary from this revision refuses to start against it, which is intended: the
  block-body commitment preimage changed too, so the two builds could not agree on
  a block even if they shared a genesis. Crossing that on a running net is the
  halt-height mechanism's job (#74), not a redeploy.

## What this harness models about the T0 hosts

Three host properties, added one at a time by issue #107's steps 1b–1d, each with its
own knob, its own readback and its own caveat. `deploy/docker/soak.sh`'s header is the
canonical list; the two sections below are the detail for the two that are
configuration rather than a qdisc.

| property | set with | read back with |
|---|---|---|
| WAN latency (1b) | `soak.sh netem <ms>` | `soak.sh netem-show` |
| advertised-address absence (1c) | `QUMBRA_ADVERTISE_ADDR=none` | `soak.sh advertise-show` |
| CPU budget (1d) | `QUMBRA_CPUS` / `QUMBRA_CPUSET`, or `soak.sh cpu-budget <n>` | `soak.sh cpu-show` |

They are **independent**, and all three default to what every run before 2026-07-30
was — no qdisc, advertised, unconstrained — so an ordinary soak is unchanged and each
of the eight combinations is reachable. Orthogonal to all three, and not a host
property at all: whether the **`faucet`** container (#123/#128) is in the run. It is a
fifth node no T0 host corresponds to, so it is excluded from every four-node
assertion — but it *mines*, so `cpu-budget` deliberately does **not** exclude it (see
`cpu_targets` in `soak.sh`). Leaving it unbudgeted next to four budgeted nodes puts an
unlimited competitor on the very cores a dedicated cpuset was meant to reserve.

**State the condition with the number, every time.** Two runs of this harness that
differ on any one of these axes are two different experiments.

## Advertised-address mode (issue #107 step 1c)

The harness can model **a node with no advertised address**, which until 2026-07-30
it could not — and that gap was not cosmetic. `entrypoint.sh` has always written
`advertise_addr`; `/opt/qumbra/node.toml` on all four T0 hosts has **never** carried
it. The field arrived with issue [#86](https://github.com/qumbra-labs/qumbra-lab/issues/86)
on 2026-07-28, the hosts were provisioned 2026-07-26, and **rolling the image does
not regenerate `node.toml`** (recorded as a dated correction in `qumbra-deploy`
OPERATOR §3). So every local run before this one was structurally incapable of
reproducing any T0 condition that depends on the field being absent.

```sh
QUMBRA_ADVERTISE_ADDR=none deploy/docker/soak.sh rehearsal   # the hosts' configuration
deploy/docker/soak.sh rehearsal                              # default: advertised
NODE2_ADVERTISE=none deploy/docker/soak.sh rehearsal          # mixed net, per node
deploy/docker/soak.sh advertise-show          # which mode each node is ACTUALLY in
deploy/docker/soak.sh advertise-show none     # …and assert it; dies on a mismatch
```

- **`auto` (default)** — `advertise_addr = "node<i>:9401"`. Unchanged behaviour;
  an ordinary soak is byte-for-byte what it was.
- **`none`** — the key is **absent** from the generated `node.toml`, not empty and
  not commented-into-a-parsed-value. The node still dials out, syncs, mines and
  votes; it is simply **never gossiped** (`entrypoint.sh`'s own note, and
  `qumbra-node`'s startup line `no advertise_addr: …`).
- Anything else is a **hard failure** at startup, not a silent fallback to `auto` —
  a typo in this variable inverts the experiment.
- `advertise-show` does **not** read the operator's environment (that would only
  prove what was *requested*). It reads the generated `node.toml` from inside each
  running container **and** the node's own startup output, and treats a disagreement
  between the two as a stop rather than something to interpret.

`none` is the hosts' configuration **on this axis only**. The hosts still differ in
kernel, architecture, RTT, tip height and uptime, so it narrows the gap rather than
closing it. State the mode alongside any number this harness produces: two runs that
differ only here are two different experiments.

## CPU budget (issue #107 step 1d)

The harness can now be held to **the T0 hosts' CPU budget**, which until 2026-07-30
it could not — and that gap was the reason three previous local runs were
structurally unable to answer the question they were asked.

```
T0 hosts        2 vCPU each      (t4g.small)
this harness    no limit at all  → four containers sharing every core the Docker VM
                                   has (18 on the dev rig)
```

The node mines RandomX **synchronously on the main loop** — the same loop that pumps
the transport and emits telemetry (`run.rs`, `run_until` → `try_mine`). Per-frame work
in `tick` therefore competes with mining **only when CPU is scarce**, and every
earlier local run was measured where it was abundant.

```sh
# a FRESH net under a limit (the durable path — compose sets it)
QUMBRA_CPUS=2 NODE0_CPUSET=0-1 NODE1_CPUSET=2-3 NODE2_CPUSET=4-5 NODE3_CPUSET=6-7 \
  deploy/docker/soak.sh rehearsal

# …and if the faucet is in the run, give it a budget and a block of its own
FAUCET_CPUS=2 FAUCET_CPUSET=8-9 \
  docker compose -f deploy/docker/docker-compose.yml up -d faucet

# or apply to a net that is already up, live, with no restart
deploy/docker/soak.sh cpu-budget 2              # quota 2 + a dedicated block each
deploy/docker/soak.sh cpu-budget 2 quota-only   # quota only; nproc stays at 18
deploy/docker/soak.sh cpu-budget none           # raise the ceiling to the whole VM
deploy/docker/soak.sh cpu-show 2                # read it back, and assert it

# all three axes at once — this composes, and each one reports itself
QUMBRA_ADVERTISE_ADDR=none QUMBRA_CPUS=2 NODE0_CPUSET=0-1 NODE1_CPUSET=2-3 \
  NODE2_CPUSET=4-5 NODE3_CPUSET=6-7 deploy/docker/soak.sh rehearsal
deploy/docker/soak.sh netem 100                 # then add ~200 ms RTT on top
```

- **Default is unconstrained.** At the defaults compose omits `cpus:`/`cpuset:` from
  the resolved config entirely (`docker compose config` shows neither key), so an
  ordinary soak is byte-for-byte what it was and `NanoCpus=0`.
- **Quota and cpuset are different experiments.** `cpus: 2` is a CFS quota — 2
  CPU-seconds per second, throttled at 100 ms period boundaries, and the container
  still *sees* all 18 cores (`nproc` = 18). `cpuset: "0-1"` is affinity — `nproc` = 2,
  which is what the hosts' own `nproc` reports. Only cpuset reproduces the topology.
  **Use a distinct block per node**: four containers pinned to the same pair are a 4:1
  oversubscription of one pair, not four 2-vCPU hosts.
- **Every container records its own budget.** `entrypoint.sh` prints one greppable line
  before the config dump, read from the container's **cgroup** rather than from the
  environment it was passed — the environment says what was requested, the cgroup says
  what the kernel will enforce:

  ```
  CPU_BUDGET node0  quota=2.00cpu       cpuset=0-1  nproc=2
  CPU_BUDGET node0  quota=unconstrained cpuset=0-17 nproc=18
  CPU_BUDGET faucet quota=2.00cpu       cpuset=8-9  nproc=2
  ```

  `soak.sh cpu-show` prints that startup line **beside** the live cgroup, because
  `cpu-budget` changes the cgroup without restarting the process and cannot rewrite a
  log line already emitted. When the two disagree, the budget was applied live.
- **The faucet is in scope for this axis and only this one.** `soak.sh cpu-budget`
  applies to the four nodes **plus `faucet` when it is running** (`cpu_targets`), and
  it appends the faucet last so `node0`…`node3` keep the same blocks either way. Every
  *other* command here — scenarios, telemetry snapshots, the netem matrix,
  `advertise-show` — excludes it, because it is a fifth node no T0 host corresponds to.
  The asymmetry is the point: a CPU budget is a claim about the machine, not about the
  topology, and the faucet mines on the same synchronous main loop the others do.
  A `cpu-budget 2 dedicated` therefore needs 10 cores rather than 8 with the faucet up,
  and says so instead of silently overlapping blocks.
- **`docker update --cpus 0` is a silent no-op** — it exits 0, prints the container
  name and changes nothing, because docker reads `0`/`""` as "leave this field alone".
  So `cpu-budget none` *raises* the ceiling to every core on the machine and says so;
  only a fresh `up` at the compose defaults gives a genuinely limit-free container.

**The limitation, stated rather than left to be discovered: `cpus: 2` on four
containers sharing one host machine is not four hosts with 2 vCPU each.** They share
one kernel scheduler, one memory-bandwidth budget and one last-level cache; the four
hosts share none of those. There is also no memory limit here — the hosts have 2 GB
and Phase B-lite measured ~262 MiB/node, so memory is not the scarce axis, but the
Docker VM's own ceiling on this rig is 8.3 GB across all four. **A limit answers "is
this effect CPU-scarcity-shaped", not "does this match the T0 net".**

The same holds for combining axes: `QUMBRA_ADVERTISE_ADDR=none` + a CPU budget + netem
is three emulations at once, not a T0 host. Each narrows the gap on its own axis and
none of them closes it, so a negative under all three still rules out only the three
shapes it tested.

## Observability

`qumbra-node run` emits a `TELEMETRY …` line to stdout on a ~30 s cadence (tip,
finalized, stall depth, chain-time age, tip difficulty, peers, mempool, epoch,
finality regime — reusing the T0-2 `Telemetry` rule). Read it with:

```sh
docker compose -f deploy/docker/docker-compose.yml logs -t -f node0   # wall-stamped
deploy/docker/soak.sh status                                          # one snapshot/node
deploy/docker/soak.sh sample 3600 60                                  # sample for an hour
```

### The cross-node agreement view (`qumbra-opview`, issue #117)

Each node also serves the **versioned `/v1/telemetry` wire** — the same
`Telemetry` snapshot the stdout line renders, carrying the finalized checkpoint's
identity (`fid`) and what that node's own keys signed (`sslot`/`sid`). It is bound
in-container by `entrypoint.sh` (`telemetry_addr = 0.0.0.0:9410`) and published to
**localhost only** on the host as 9410–9413 for node0–node3.

```sh
cargo run -p qumbra-opview -- \
  node0=http://127.0.0.1:9410 node1=http://127.0.0.1:9411 \
  node2=http://127.0.0.1:9412 node3=http://127.0.0.1:9413
```

It prints one row per node and then two verdicts, kept deliberately apart:

- **`fid` divergence** — two nodes reporting the *same* `final` with *different*
  identities, i.e. two checkpoints finalized at one height. **The R2 STOP.** It is
  the only condition that exits non-zero (exit `2`).
- **`sid` divergence** — nodes whose own keys signed different variants at one
  slot. A **finding**, not a stop, and exit `0`: the minority still finalizes the
  majority's checkpoint, so `fid` can agree while this does not.

A node that does not answer is rendered `UNREACHABLE` with its reason and is
excluded from both verdicts — a timeout is missing evidence, not a disagreement,
and exits `0`. Endpoint list is operational config: with one entry it is a
single-node health page, with four it is the agreement view, over one code path.

> **This is the T0 operator view, not `testnet-plan` §6's T1 explorer.** "These
> four nodes agree" is the whole truth here, because these four hosts *are* the
> network. It does not generalise to a public net, where the same output would be
> the operator's own nodes vouching for themselves.

**A node built before #117 is refused, not best-effort parsed**: its wire is
`0x01`, this build speaks `0x02`, and a `fid=-` rendered from an unreadable body
would look exactly like a node that had finalized nothing. The image must be
rebuilt for the view to read anything (`deny_unknown_fields` also means an old
binary refuses the new config outright — ship the binary first).

### The faucet (`qumbra-faucet`, issue #123)

A **fifth** container, and deliberately not one of the four: it holds **no committee
keys**, because `testnet-plan.md` §6.2 rules that a node holding committee keys
exposes nothing beyond P2P — so the faucet's hot spending key never shares a host
with them. `qumbra-faucet` **refuses to start** if its node config names any key
file, so this is enforced rather than documented.

```sh
docker compose -f deploy/docker/docker-compose.yml up -d --build faucet
open http://127.0.0.1:9450/                    # the page a person uses
curl http://127.0.0.1:9414/v1/telemetry        # its keyless node's telemetry
docker exec qumbra-t0-lite-faucet-1 \
    qumbra-faucet ticket --config /data/faucet.toml --id 1   # one single-use ticket
```

The in-container bind is `0.0.0.0:9450` — a private bridge namespace, the same
argument this file already makes for `telemetry_addr` — and compose publishes it to
**`127.0.0.1` on the host**, which is where the exposure decision actually lives. On a
real host, off-loopback is a deliberate act paired with a source-restricted inbound
rule, and the binary says so loudly at every startup that is not on loopback.

Key material is minted **once** into the faucet's own volume (`0600`) and reused
across restarts, so the faucet keeps what it has mined. `QUMBRA_FAUCET_TICKETS=open`
turns tickets off; `qlab_faucet::policy` prices exactly what that costs (saturable by
roughly a hundred distinct subnets).

🔴 **It cannot serve a grant on a fresh net for ~3 h.** `COINBASE_MATURITY_BLOCKS` =
144 (FROZEN §2) at the frozen 75 s block time, and a 2×2 bucket needs **two** matured
notes. Until then the page names the height it changes at and **refuses** rather than
queueing a request it cannot honour. Two further blockers are recorded on issue #123
and are not fixed: a recipient cannot detect a grant on a net whose nodes serve no
note discovery, and a node's state machine desynchronises permanently from its own
chain once it falls one block behind.

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

Added for [#107](https://github.com/qumbra-labs/qumbra-lab/issues/107) step 1b, where a
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
