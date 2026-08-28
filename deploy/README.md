# Qumbra T0 internal-net deploy tooling (M10-T0-3 item 1)

`rsync`/`ssh`-grade deploy for the 4-VPS T0 rehearsal — **no k8s, no containers**.
Builds the `qumbra-node` binary, mints one shared genesis + the 21 committee
signing keys, and lays down a per-node payload (binary + genesis + that node's key
subset + a generated config) onto each host.

- **`deploy.sh`** — the tool (build → genesis → per-node config → stage → push).
- **`dry-run.sh`** — Phase-A: run the whole deploy against 4 **local directories**
  standing in for the hosts, then assert the layout is correct and startable.
- **`hosts.example`** — the 4-node host spec (fill in real IPs for Phase B). Since
  lab #475 it carries a **4th column, `miner_rkm`** — the per-host coinbase payee
  — and it is the **source of truth** for that field. Since lab #552 that column
  is **required on every host of a mining fleet** (the default): `qumbra-node`
  refuses to start with `mining = true` and no `miner_rkm`, so `deploy.sh`
  refuses to *generate* one, naming every keyless host before it builds. `-` (or
  an omitted column) is legal only under `--no-mining`, and the file as shipped
  is such a template — no placeholder keys, deliberately.
- **`qumbra-node.service.example`** — optional systemd unit for the VPS.

## The T0 topology (inline stamps, per the task-book)

- **N_machines = 4** — allows a 2+2 partition (soak scenario (c)).
- **21 committee keys split 6/5/5/5** across the 4 nodes (listed order). A 2+2
  partition leaves ≤ 11 keys either side, below the 15-quorum — so finality
  **correctly stalls** under partition (that is the behavior scenarios (c)/(d)
  test; it is not a bug).
- **Full mesh**: each node dials the other three (`dial_peers`).
- All 4 nodes mine (real RandomX) and hold keys, so any 3 nodes reachable ⇒
  quorum ⇒ finality proceeds.

## Phase A — the local dry-run (no VPS)

```sh
deploy/dry-run.sh            # builds if needed, lays down 4 node dirs, asserts, cleans up
deploy/dry-run.sh --keep     # keep the tree to inspect it
```

It writes a local hosts spec (`127.0.0.1:9401..9404`, ssh target `-`, a distinct
`miner_rkm` on every host), invokes `deploy.sh` in local mode, and checks: every
payload present; the 21 keys split 6/5/5/5 disjoint + complete; the genesis file
byte-identical on all 4 nodes; `qumbra-node check` passing on every node with a
single shared pinned genesis hash, reporting `mining = true` and that host's own
payout key; the **committee key modes — 0700 on `keys/`, 0600 on each key file**;
and each host's `miner_rkm` reaching **that host's config, verbatim and alone**,
and surviving a re-deploy. Two further passes pin the **payout contract** (lab
#552): a mining fleet with keyless hosts is **refused at generation** — before
the genesis is minted or a payload exists, naming every keyless host and the
`--no-mining` exit — and the same mixed fleet under `--no-mining` generates
cleanly, every node preflighting with `mining = false`. Exits non-zero on the
first failed assertion.

🔴 **`dry-run.sh` runs in CI only when `deploy/**` or `crates/qumbra-node/**`
changes** (`.github/workflows/deploy-dryrun.yml`, from PR #670's review). The cargo
suite does not run it and nothing in `crates/` shells out to `deploy.sh`, so on a PR
that touches neither path the tick still says nothing about this directory. The
node path is in the filter because `qumbra-node check` is this script's acceptance
and PR #655 broke it from `crates/qumbra-node/` alone. After touching anything
here, the `deploy dry-run` check is the evidence — link it, or paste a local run.

The mode check runs three times over and is worth understanding before editing it.
On 2026-07-31 the T0 net was found with `drwxr-xr-x /opt/qumbra/keys` while every
key file inside was correctly `0600`: `genesis init` sets both modes, but
`deploy.sh` re-created the staging directory under the default umask and
`rsync -a` faithfully carried `0755` to four public-IP hosts. So:

1. the **deployed** tree is asserted — the fresh-deploy case,
2. the **staging** tree is asserted (`deploy.sh --keep-stage` now prints its path)
   — the modes at the site where they are set, not one transport downstream,
3. the deployed tree is asserted **again after a re-deploy** over a `keys/` that
   was deliberately loosened back to `0755` — because `rsync -a --delete` rewrites
   an existing directory's mode but `cp -R` (local mode) does not, so the two
   transports disagree on whether a pre-fix tree self-repairs.

A check that looked only at file modes, or only at the deployed copy, would have
passed at every point in that history.

## Phase B-WAN — VPS provisioning requirements **[manual — Larry]** ✅ DISCHARGED 2026-07-26

> **The gate is closed and the net is live since 2026-07-26 15:43.** Provisioning is no longer manual: it is
> Terraform in the private [`qumbra-deploy`](https://github.com/qumbra-labs/qumbra-deploy) repo — 4 × `t4g.small`
> (Graviton/arm64, Debian 12) across us-east-1 · eu-west-1 · ap-southeast-1 · ap-northeast-1, measured
> inter-node RTT **68–223 ms**. Operations run as **T-ops**; the live state lives in `qumbra-deploy/OPERATOR.md`.
> The requirements below are preserved as the record of what was asked for and why — several of them were
> confirmed by the build, and one was **wrong in a way worth keeping visible**: see the NAT note at the end.

Written by the coordinator 2026-07-25 against the issue #64 `[manual]` clause, what
this tooling actually needs from a host, and the **measured** Phase B-lite resource
envelope (`docs/m10-t03-phase-b-lite-run.md` §6). Hard requirements are marked; the
rest is recommendation with its grounds.

**Architecture — pick arm64 unless there's a reason not to.** Phase B-lite proved
the whole RandomX build/link/mine path on **aarch64 Debian bookworm**, and that
Dockerfile (`deploy/docker/`) is a reusable VPS image. x86_64 works in principle but
that path is *unvalidated here*, and the dev rig is arm — so an x86 target means
either emulated builds or building on the VPS itself. **HARD: a macOS-built binary
cannot run on the VPS** (the `randomx-rs` C dependency) — build on Linux of the same
architecture.

| Item | Requirement | Why |
|---|---|---|
| Machines | **exactly 4** (hard) | issue #64 topology stamp: allows the 2+2 partition scenario; 21 committee keys split 6/5/5/5 |
| RAM | ≥ 4 GB (**measured use: ~262 MiB/node**) | RandomX *light* cache (256 MB) + node; the spec is deliberately generous — do not pay extra here |
| vCPU | **2** (not 1) | one core saturates while hashing at the 75 s tick; the second keeps P2P + telemetry from starving |
| Disk | 20–40 GB | measured: 4–8 KB of chain data for ~388 coinbase-only blocks. Disk is for logs/telemetry, not the chain |
| OS | Debian 12 / Ubuntu 22.04+, **arm64 preferred** | matches the proven B-lite image |
| Public address | **routable public IP + one inbound TCP port open** (default `9444`, see `hosts.example`) — hard | peers dial each other directly; **NAT traversal is an M11 item, out of scope for T0** |
| Geography | **≥ 3 regions, intercontinental** (e.g. SG / EU / US-E / US-W) | real RTT is the *only* new variable Phase B-WAN adds over B-lite. Four hosts in one DC measure nothing new: the owed items are checkpoint cadence 8 at real RTT and LWMA at real 75 s pacing |
| Privileges | root / sudo | the 2+2 partition is produced with host firewall rules (iptables/nftables), not a provider console |
| Host tooling | `rsync`, ssh key access, systemd | `deploy.sh` is rsync/ssh-grade; `qumbra-node.service.example` is a systemd unit |

**Larry's manual steps** (duration outside Claude's control): provision the 4 hosts;
open the port and confirm they are **not** behind NAT; install ssh keys and hand the
access to the executing session; choose arm64 vs x86_64.

**Sequencing.** Provision any time, but the *full* run belongs **after the [#70]
vote-aggregation baton (M10-T0-5) merges** — for the same reason B-lite deferred its
partition and committee-stall scenarios: with no distributed finality there is
nothing to observe in scenarios (c)/(d), and the run would only reproduce B-lite's
`Degraded` result. Runnable before T0-5: genesis rehearsal, (a) late-joiner sync,
(b) mining-node restart, and a real-RTT baseline telemetry sample.

**Duration/cost shape**: the soak is **≥ 48 h continuous**, plus the scenario passes
and a re-run after T0-5 — budget roughly a week of uptime on four small instances.

[#70]: https://github.com/qumbra-labs/qumbra-lab/issues/70

## Phase B — the real 4-VPS deploy ✅ executed 2026-07-26 (see `qumbra-deploy`)

1. Edit `hosts.example` → `hosts` with the 4 VPS public addresses + ssh targets,
   and **every host's `miner_rkm`** in the 4th column (`qumbra-wallet miner-rkm
   --dir DIR` prints the value). Since lab #552 a mining host without one is a
   config `qumbra-node` refuses to start — every coin it mined went to a key
   nobody holds — so `deploy.sh` refuses to generate it and names the hosts. `-`
   or an omitted column is legal only with `--no-mining` (a verify-only
   rehearsal in which no host mines); the tool never flips a host to
   `mining = false` for you.

   🔴 **Put it in the hosts file, never on the host.** Before lab #475 the
   generator emitted no `miner_rkm` at all, so every re-run dropped the field
   from each host that had one and it was restored by hand afterwards — the
   standing red of `qumbra-deploy/OPERATOR.md` §9.5.1. A config edited on the
   host is overwritten by the next deploy; the hosts file is what survives
   regeneration, and `dry-run.sh` asserts exactly that.
2. Build a **Linux** binary (see the cross-compile caveat below).
3. Deploy:
   ```sh
   deploy/deploy.sh --hosts deploy/hosts --remote-root /opt/qumbra \
                    --target x86_64-unknown-linux-gnu
   ```
4. On each VPS, pre-flight then start:
   ```sh
   /opt/qumbra/qumbra-node check --config /opt/qumbra/node.toml
   (cd /opt/qumbra && ./qumbra-node run --config node.toml)
   # or install qumbra-node.service.example and: systemctl enable --now qumbra-node
   ```

### RandomX / cross-compile caveat (important)

The binary links `randomx-rs` (a C library). A binary built on the macOS dev rig
will **not** run on a Linux VPS. Build the Linux binary either:

- **on a Linux host / container** matching the VPS (simplest, recommended), or
- via a cross toolchain with the RandomX C deps available for the target
  (`--target x86_64-unknown-linux-gnu`).

`deploy.sh --target …` passes the triple through to `cargo build`, but does **not**
solve RandomX's C-dependency cross-build — provisioning that toolchain is a
per-environment step outside this script. RandomX **light mode** (what the node
uses) fits the ≥ 4 GB / 2 vCPU VPS spec.

## What deploy.sh guarantees

- One genesis file, one genesis hash, pinned into every node's config
  (`expected_genesis_hash`) — a node started against a different genesis refuses
  to boot (item 2).
- Each node receives **only** the committee keys it holds (key distribution, not a
  blanket copy), in a `keys/` directory set to **0700 explicitly at creation** —
  both transports preserve modes, so the staged mode is the mode on the host.
  `$node_root` itself (`/opt/qumbra`) is deliberately left at the operator's umask:
  it holds `genesis.qmb` (public and hash-pinned), `node.toml` (addresses and key
  *paths*, no key material), the binary and `data/`.
- Configs carry absolute destination paths, so the same payload works whether the
  root is a local dry-run dir or `/opt/qumbra` on a VPS.

## Phase B is NOT run by this tooling

Genesis rehearsal, the four WAN soak scenarios, the ≥ 48 h telemetry-sampled run,
and the T0 evidence pack resume on this branch once the 4 VPSes exist. This
directory only provisions; it does not orchestrate the soak.


## Correction: "no NAT" was the wrong phrasing

The requirements table above lists *"routable public IP, no NAT"* as hard. Read literally that would have
disqualified EC2, whose public IPv4 is a 1:1 mapping onto an interface the instance never sees — and EC2 is
what the net actually runs on.

**What the requirement means is that no NAT *traversal* is implemented** (hole punching is an M11 item), not
that address translation anywhere in the path is fatal. Nodes bind `listen_addr` and dial an explicit
`dial_peers` list; nothing self-discovers or self-advertises an address, so a security group allowing inbound
on the P2P port is sufficient. `deploy.sh` already sets `listen = 0.0.0.0:<port>` for real hosts, which is why
this was a wording defect and not a deployment one.

Kept rather than silently reworded: a requirement that would have excluded the platform the project went on to
use is worth leaving visible, because the next hard-sounding constraint in that table may be equally imprecise.
