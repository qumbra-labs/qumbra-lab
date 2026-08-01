# M10-T0-3 Phase A — status (wall-clock timestamps + deploy tooling)

Issue [#64](https://github.com/qumbra-labs/qumbra-lab/issues/64) (M10 wave 2). This branch
(`claude/m10-t03`) delivers **Phase A** — the two pieces that need no VPS. **Phase B
(genesis rehearsal, the four WAN soak scenarios, the ≥ 48 h telemetry run, and the
T0 evidence pack) resumes on this same branch once Larry provides the 4 VPSes.**

## Item 0 — wall-clock header timestamps (issue amendment, precondition)

**Problem (from PR #65 acceptance):** the binary advanced header timestamps by a
constant 75 s per block (the deterministic mining clock), so LWMA saw a constant
solvetime and difficulty never left the genesis value — which would make the
task-book's item-4 "LWMA difficulty trace under real cadence" measurement vacuous.

**Fix:** a `MiningClock` seam on `qlab_p2p::adapter::NodeAdapter`:

- `MiningClock::Deterministic` (default) — the existing monotone counter
  (`parent.timestamp + block_time`). **Every in-process sim/test keeps this**, so
  runs stay reproducible.
- `MiningClock::WallClock` — real `SystemTime::now()` seconds, clamped
  non-decreasing against the parent so header validation's monotonic rule always
  holds. The **binary** (`qumbra-node run`) opts into this in `run_node`.

The seam is `NodeAdapter::next_timestamp()`, called from `mine_block()`. Validation
already tolerates the jitter: `validate_header`'s non-decreasing rule +
`lwma_next_difficulty`'s 6T clamp / out-of-sequence guard (no changes needed there).

The `qlab-devnet` `SimNode` clock (`node.rs`) is **untouched** — it is the
in-process sim path and stays deterministic per the amendment.

**Tests (both green):**
- `qlab-p2p` `adapter::tests::mining_clock_default_is_deterministic_binary_uses_wall_clock`
  — the default gives `parent + block_time`; `WallClock` gives a real wall-clock
  second bracketed by `now()` and far larger than the constant clock.
- `qlab-devnet`
  `validation::tests::lwma_trace_is_flat_under_a_constant_clock_and_moves_under_variable_solvetimes`
  — the exact T0-1 defect→fix contrast: a constant clock ⇒ a **flat** LWMA trace
  (1 distinct difficulty); wall-clock-like variable solvetimes ⇒ a **non-constant**
  trace.

## Item 1 — deploy tooling (`deploy/`, rsync/ssh grade, no k8s)

- `deploy/deploy.sh` — builds the binary, mints ONE genesis + the 21 committee
  keys, then per node generates a config (listen addr, full-mesh dial peers, the
  pinned genesis hash, and only that node's key subset), stages a payload, and
  deploys it — local dir (dry-run) or `rsync`/`ssh` (real host).
- `deploy/dry-run.sh` — Phase-A local dry-run harness + assertions.
- `deploy/hosts.example`, `deploy/qumbra-node.service.example`, `deploy/README.md`.
- A read-only `qumbra-node check --config FILE` subcommand (lib fn
  `qumbra_node::run::preflight`) validates a deployed config through the real
  startup checks (genesis byte-verify + hash pin + each held key cross-checked
  against committee₀) **without binding a socket or touching disk state**.

**Topology (task-book inline stamps):** N_machines = 4 (allows a 2+2 partition);
21 committee keys split **6/5/5/5**; full mesh. A 2+2 partition leaves ≤ 11 keys
either side (< 15 quorum) ⇒ finality **correctly stalls** under partition — the
behavior soak scenarios (c)/(d) exercise, not a bug.

## Item 1b — the local dry-run (evidence)

`deploy/dry-run.sh --keep` lays the whole deploy down against 4 local directories
standing in for the hosts and asserts:

1. every node dir has the binary + `genesis.qmb` + `node.toml` + its key subset;
2. the 21 keys split 6/5/5/5, **disjoint + complete** (union == committee-00..20);
3. `genesis.qmb` is **byte-identical** on all 4 nodes;
4. the deployed `qumbra-node check` passes on every node, all pinned to the same
   genesis hash `4a75b3b8…c2c3` (the frozen T0-1 genesis — matches PR #65).

Result: **DRY-RUN PASSED** (node0 = 6 keys, node1/2/3 = 5 keys each; one shared
genesis hash across all four). Reproduced on the dev rig; re-runnable by the
coordinator via `deploy/dry-run.sh`.

## Cross-compile caveat for Phase B (recorded)

The binary links `randomx-rs` (a C library); a macOS-built binary will not run on a
Linux VPS. Build the Linux binary on a Linux host/container matching the VPS (or a
cross toolchain with the RandomX C deps for the target). `deploy.sh --target`
passes the triple to cargo but does not itself solve RandomX's C cross-build.
RandomX **light mode** (what the node uses) fits the ≥ 4 GB / 2 vCPU VPS spec.

## Phase B checklist (NOT started — gated on 4 VPSes)

- [ ] genesis rehearsal: all 4 nodes byte-verify the same genesis, mine from
      genesis at the frozen 75 s under real RandomX;
- [ ] soak (a) sync-from-genesis of a late joiner;
- [ ] soak (b) restart of a mining node (open == replay on real disk);
- [ ] soak (c) partition 2+2 → heal (fork-choice converges, finality never
      overreaches);
- [ ] soak (d) committee stall → recovery via the T0-2 flow;
- [ ] ≥ 48 h continuous run with telemetry sampling;
- [ ] measurements: checkpoint cadence at WAN RTT, LWMA difficulty trace at real
      75 s cadence (now non-constant thanks to item 0), orphan/stale rate, per-node
      RAM/disk/CPU;
- [ ] the T0 evidence pack (rig specs per VPS, telemetry traces, honest findings) —
      M11's entry gate.

**STOP-POINT reminder for Phase B:** any consensus misbehavior (fork past finality,
supply mismatch, double-finalization) → STOP the soak, preserve state, report — do
not patch-and-continue.
