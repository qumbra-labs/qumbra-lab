# Qumbra T0 internal-net deploy tooling (M10-T0-3 item 1)

`rsync`/`ssh`-grade deploy for the 4-VPS T0 rehearsal — **no k8s, no containers**.
Builds the `qumbra-node` binary, mints one shared genesis + the 21 committee
signing keys, and lays down a per-node payload (binary + genesis + that node's key
subset + a generated config) onto each host.

- **`deploy.sh`** — the tool (build → genesis → per-node config → stage → push).
- **`dry-run.sh`** — Phase-A: run the whole deploy against 4 **local directories**
  standing in for the hosts, then assert the layout is correct and startable.
- **`hosts.example`** — the 4-node host spec (fill in real IPs for Phase B).
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

It writes a local hosts spec (`127.0.0.1:9401..9404`, ssh target `-`), invokes
`deploy.sh` in local mode, and checks: every payload present; the 21 keys split
6/5/5/5 disjoint + complete; the genesis file byte-identical on all 4 nodes; and
`qumbra-node check` passing on every node with a single shared pinned genesis
hash. Exits non-zero on the first failed assertion.

## Phase B — the real 4-VPS deploy (gated on Larry's VPSes)

1. Edit `hosts.example` → `hosts` with the 4 VPS public addresses + ssh targets.
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
  blanket copy).
- Configs carry absolute destination paths, so the same payload works whether the
  root is a local dry-run dir or `/opt/qumbra` on a VPS.

## Phase B is NOT run by this tooling

Genesis rehearsal, the four WAN soak scenarios, the ≥ 48 h telemetry-sampled run,
and the T0 evidence pack resume on this branch once the 4 VPSes exist. This
directory only provisions; it does not orchestrate the soak.
