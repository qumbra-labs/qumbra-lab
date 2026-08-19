#!/usr/bin/env bash
#
# Phase B-lite soak driver (M10-T0-3, issue #64 amendment 3) — the docker/localhost
# rehearsal of the Phase-B protocol. Each scenario is a subcommand so the operator
# runs them one at a time and reads the telemetry between steps (STOP-POINT
# discipline: on any consensus misbehavior, STOP and preserve state — do not
# patch-and-continue).
#
#   soak.sh rehearsal            build + genesis rehearsal (assert pinned hash) + up
#   soak.sh status               one telemetry snapshot per node
#   soak.sh sample <secs> [ivl]  print each node's telemetry every <ivl>s for <secs>
#   soak.sh latejoiner           node3 joins late → sync-from-genesis
#   soak.sh restart <node>       stop+start a node → open==replay on its volume
#   soak.sh partition            true 2+2 split (docker network disconnect)
#   soak.sh heal                 reconnect the partition → converge + finality resume
#   soak.sh committee-stall      stop 3 key-holders → Degraded (quorum lost)
#   soak.sh committee-recover    restart them → T0-2 catch-up → Final
#   soak.sh teardown             docker compose down -v (destroys volumes)
#
# ── WHAT THIS HARNESS MODELS ABOUT THE T0 HOSTS ──────────────────────────────
#
# THREE host properties, added one at a time by issue #107's steps 1b–1d, and this is
# the one place they are listed together. Each is a separate knob with a separate
# readback and a separate caveat, and NONE of them reads any other:
#
#   property                     set with                    read back with
#   ───────────────────────────  ──────────────────────────  ────────────────────────
#   WAN latency          (1b)    soak.sh netem <ms>          soak.sh netem-show
#   advertised-addr absence (1c) QUMBRA_ADVERTISE_ADDR=none  soak.sh advertise-show
#   CPU budget           (1d)    QUMBRA_CPUS / QUMBRA_CPUSET soak.sh cpu-show
#                                or soak.sh cpu-budget <n>
#
# All three DEFAULT to what every run before 2026-07-30 was — no qdisc, advertised,
# unconstrained — so an ordinary soak is unchanged and each of the eight combinations
# is reachable and legible. A fourth axis is orthogonal to all of them and is not a
# host property at all: whether the `faucet` container (#128) is in the run. It is a
# FIFTH node that none of the four T0 hosts corresponds to, so it is excluded from
# every four-node assertion here — but it mines, so it is NOT excluded from the CPU
# budget (see cpu_targets).
#
# Two rules that apply to all three, and they are why the knobs exist at all:
#
#   1. STATE THE CONDITION WITH THE NUMBER. Two runs of this harness that differ on
#      any one of these axes are two different experiments. Every readback command
#      prints, and most will assert, so there is no reason to infer.
#   2. A KNOB ANSWERS "IS THIS EFFECT <X>-SHAPED", NEVER "DOES THIS MATCH T0". Each
#      section below says exactly what its own negative result does and does not rule
#      out. Read the one you used before quoting anything from it.
#
# LATENCY INJECTION (issue #107 step 1b). Run against a net that is already up.
#
#   soak.sh netem <delay_ms> [jit_ms]  install `tc netem` on every node's eth0,
#                                      then PROVE it took (qdisc + measured RTT).
#                                      The delay is ONE-WAY, so RTT is ~twice it.
#   soak.sh netem d0,d1,d2,d3 [jit]    per-node one-way delays — the asymmetric case,
#                                      where pair RTT = d_i + d_j (e.g. 30,60,90,110)
#   soak.sh netem-show                 the qdisc + the measured RTT matrix
#   soak.sh netem-clear                remove it, and prove it is gone
#
# ADVERTISED-ADDRESS MODE (issue #107 step 1c). Set on the compose service, read
# back from the running containers:
#
#   QUMBRA_ADVERTISE_ADDR=none soak.sh rehearsal   bring the net up with NO node
#                                      advertising itself — the four T0 hosts' own
#                                      configuration. Default (unset) = advertised,
#                                      i.e. every run before 2026-07-30.
#   soak.sh advertise-show [auto|none] which mode each node is ACTUALLY in, read from
#                                      the generated node.toml inside each container
#                                      and from the node's own startup output. With
#                                      an argument it asserts and dies on a mismatch.
#
# CPU BUDGET (issue #107 step 1d). Two ways in, because they answer different
# questions; both default to UNCONSTRAINED, which is what every run before
# 2026-07-30 was.
#
#   QUMBRA_CPUS=2 QUMBRA_CPUSET=... soak.sh rehearsal
#                                      a FRESH net under a limit, set on the compose
#                                      service. This is the durable path — see
#                                      docker-compose.yml. Prefer per-node
#                                      NODE<i>_CPUSET so the four do not share cores,
#                                      and FAUCET_CPUS/FAUCET_CPUSET if the faucet is
#                                      in the run (it mines; see cpu_targets below).
#   soak.sh cpu-budget <n> [quota-only]
#                                      apply to a net that is ALREADY UP, live, with
#                                      no restart: quota n CPU + a DISTINCT n-core
#                                      block per container (`quota-only` omits the
#                                      cpuset, leaving `nproc` at the host count). Same
#                                      idiom as `netem` — it is what lets one net be
#                                      measured under two budgets with the build,
#                                      tip range and process lifetime held fixed.
#   soak.sh cpu-budget none            raise the ceiling back to the whole VM. NOT the
#                                      same as never having had a limit — see the
#                                      `docker update --cpus 0` trap below.
#   soak.sh cpu-show [n|none]          what each container ACTUALLY has, read from its
#                                      own cgroup, plus whether that still matches the
#                                      budget it booted with. With an argument it
#                                      asserts and dies on a mismatch.
#
# HALT-HEIGHT UPGRADE DRILL (issue #74). Run in order; each prints its own
# assertions and STOPS on a violation. H = 16 (on the cadence grid of 8).
#
#   soak.sh halt-arm             fresh net: node0/1/2 on the ARMED binary, node3 on
#                                the plain v1.0 binary (the §4 old-binary miner —
#                                it never deployed the halt, so it never halts).
#                                Runs to H and asserts the halt.
#   soak.sh halt-drill-b         (b) N2: upgrade only node0+node1 (11 keys < 15)
#                                → finality must NOT resume
#   soak.sh halt-drill-a         (a) H3: upgrade node2 too (16 keys ≥ 15) → finality
#                                resumes past H while node3's old-rule branch grows
#                                and NEVER finalizes
#   soak.sh halt-drill-c         (c) H4: start node2 on the no-revision binary →
#                                must REFUSE to start
#   soak.sh halt-drill-d         (d) N1: fresh net, all nodes on the CANCELLED
#                                binary → mines straight through H, never halts
#   soak.sh halt-status          per-node halt view (tip / final / regime / halt)
#   soak.sh halt-evidence        append full telemetry + raw refusal reasons to
#                                docs/m11-halt-height-evidence.log
#
# LOCALHOST/DOCKER. Real RandomX light, WallClock, frozen 75 s block time.
#
# LATENCY: the bridge is loopback-fast (sub-millisecond RTT) unless you inject delay
# with `netem` above. This used to read "no WAN-latency claims", which was true of the
# harness but became the reason a WAN-vs-local question could not be settled here
# (#107 step 1). What is true now:
#
#   * A run with NO netem is a ZERO-LATENCY run. Do not quote its numbers as WAN
#     numbers, and do not quote them as evidence ABOUT latency either — that was the
#     old disclaimer's real content and it still holds.
#   * A run WITH netem models an emulated, UNIFORM, symmetric delay. State it as
#     "<delay> ms one-way netem on every node (RTT ~<2*delay> ms)", never as "WAN".
#     The real T0 WAN is none of those things: its measured 68-223 ms RTT baseline is
#     per-pair and asymmetric, it carries jitter and loss this does not, and its hosts
#     are t4g.small Graviton VMs rather than containers on one machine.
#   * `netem` therefore answers "is this effect latency-SHAPED", not "does this match
#     the T0 net". A negative result under netem rules out delay-as-such; it does not
#     rule out the WAN.
#
# CONFIGURATION FIDELITY: the harness can now model a node with NO advertised
# address, which until 2026-07-30 it could not. This is not a convenience knob.
# `entrypoint.sh` has always written `advertise_addr`, while /opt/qumbra/node.toml on
# all four T0 hosts has never carried it — the field arrived with issue #86 on
# 2026-07-28, the hosts were provisioned 2026-07-26, and rolling the image does not
# regenerate node.toml. So every local run was structurally incapable of reproducing
# a T0 condition that depends on the field being absent, and issue #107's first two
# local negatives could not have been anything else. What is true now:
#
#   * A default run (`auto`) has every node advertising itself dialable. That is a
#     LOCAL configuration; do not present its numbers as the hosts' behaviour.
#   * `QUMBRA_ADVERTISE_ADDR=none` is the hosts' configuration on this axis, and only
#     on this axis. The hosts still differ in kernel, arch, RTT, tip height and
#     uptime, so `none` narrows the gap rather than closing it.
#   * A node with no `advertise_addr` still dials out, syncs, mines and votes; it is
#     never GOSSIPED, so nobody learns it who was not configured with it. On this
#     full-mesh net every node is a configured seed of every other, which is why the
#     mesh still forms in `none` mode — and why `dialable=`/`peers=` are the fields to
#     watch when comparing the two modes.
#   * State the mode with the numbers, every time. Two runs of this harness that
#     differ only here are two different experiments.
#
# CPU: the harness can now be held to the T0 hosts' CPU budget, which until
# 2026-07-30 it could not. The four hosts are `t4g.small` — 2 vCPU each — and these
# four containers had no limit at all, so they shared every core the Docker VM has
# (18 on the dev rig). That mattered rather than being a detail: the node mines
# RandomX **synchronously on the main loop**, the same loop that pumps the transport
# and emits telemetry, so per-frame work in `tick` competes with mining only when CPU
# is scarce. What is true now:
#
#   * A run with NO CPU limit is a CPU-ABUNDANT run, and it says NOTHING about
#     CPU-scarce behaviour. That is the whole reason this knob exists — issue #107's
#     first three local negatives were all measured where CPU was abundant, so none of
#     them could have observed an effect that only appears when it is not.
#   * A run WITH a limit models an emulated budget, and `cpus: 2` × 4 containers on one
#     host machine is NOT four hosts with 2 vCPU each. They share one kernel scheduler,
#     one memory-bandwidth budget and one LLC; the hosts share none of those. State it
#     as "quota 2 CPU per container, N-core dedicated block each, one Docker VM",
#     never as "2 vCPU hosts".
#   * QUOTA AND CPUSET ARE DIFFERENT EXPERIMENTS. `--cpus 2` is a CFS quota: the
#     container still SEES every core (`nproc` = 18) and is throttled at 100 ms period
#     boundaries. `--cpuset-cpus 0-1` is affinity: `nproc` = 2, which is what the T0
#     hosts' own `nproc` reports. Only cpuset reproduces the topology; only quota
#     reproduces a share smaller than a whole core. Say which one a number came from.
#   * A CPU limit therefore answers "is this effect CPU-SCARCITY-shaped", not "does
#     this match the T0 net". A negative under a limit rules out scarcity-as-such on
#     this rig; it does not rule out the hosts.
#   * There is no MEMORY limit here and this section does not add one. The hosts have
#     2 GB; Phase B-lite measured ~262 MiB/node, so memory is not the scarce axis — but
#     the Docker VM's own ceiling on this rig is 8.3 GB for all four, which is not
#     "abundant" in the way the core count is. `docker info` is the caliper.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="$SCRIPT_DIR/docker-compose.yml"
NET_MAIN=qumbra_t0
NET_SIDEB=qumbra_t0_sideb
# The genesis identity has MOVED TWICE since the T0 net was minted, so this is the
# value THIS TREE builds, not the value any host is running:
#   issue #101 — StoredBlock gained `coinbase_rkm`, so the embedded genesis block
#                changed (4a75b3b8…c2c3 → 8811d4e0…3cff).
#   issue #115 — the genesis header now commits to its own body, deliberately, at
#                the mint (8811d4e0…3cff → the value below).
# The T0 net on t0-wan-2 is still pinned to the pre-#101 4a75b3b8…c2c3 and a binary
# from this revision will refuse to start against it — deliberately, since the
# block-body format changed too and the two could not agree anyway. Keep this in
# step with `qumbra_node::genesis::tests::genesis_hash_is_pinned`; the operator-side
# pin (qumbra-deploy OPERATOR.md) moves separately, in the same act as the mint.
PINNED_GENESIS=bd3604804aade38ece989d87e72e3541cede939512f513840c5cdcf13986a66f
NODES=(node0 node1 node2 node3)
# The halt height compiled into the drill binaries (release.rs DRILL_HALT_HEIGHT).
# On the checkpoint-cadence grid (16 = 2 x 8), deliberately low so each drill is
# minutes. Keep in step with the Rust constant.
HALT_H=16

dc()  { docker compose -f "$COMPOSE" "$@"; }
cid() { dc ps -q "$1"; }

die() { echo "soak: $*" >&2; exit 1; }

# RIG DISCIPLINE — refuse to start heavy docker work while the b4 bench runs.
guard_rig() {
  if pgrep -f qlab_bench >/dev/null 2>&1; then
    die "b4 bench (qlab_bench) is running — do NOT build/up now (OOM risk). Wait it out."
  fi
}

# The latest TELEMETRY line a node has emitted (stdout, captured by docker logs).
# `|| true`: a node with no telemetry yet (just wiped / not started) makes grep
# exit non-zero, which would abort the script under `set -o pipefail`.
# Content-anchored, not `^`-anchored (lab #512): the line carries a native UTC
# stamp now, and this pattern matches both the stamped and pre-#512 formats.
latest() { dc logs --no-log-prefix "$1" 2>/dev/null | grep 'TELEMETRY tip=' | tail -1 || true; }

# Extract key=value from a telemetry line.
field() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" <<<"$1"; }

snapshot() {
  for n in "${NODES[@]}"; do
    local line; line="$(latest "$n")"
    if [[ -z "$line" ]]; then
      printf '  %-6s (no telemetry yet / down)\n' "$n"
    else
      printf '  %-6s tip=%-4s final=%-4s stall=%-3s diff=%-6s peers=%-2s regime=%s\n' \
        "$n" "$(field "$line" tip)" "$(field "$line" final)" \
        "$(field "$line" stall)" "$(field "$line" diff)" \
        "$(field "$line" peers)" "$(field "$line" regime)"
    fi
  done
}

# ── latency injection (issue #107 step 1b) ──────────────────────────────────
#
# THE ARGUMENT IS ONE-WAY DELAY, NOT RTT. `tc netem delay` delays a container's
# EGRESS, so a packet pays the sender's delay and its reply pays the replier's:
#
#   RTT(i,j) = delay_i + delay_j        (uniform delay d  =>  RTT ~= 2d)
#
# So `netem 100` models the ~200 ms end of the measured 68-223 ms T0 WAN RTT
# baseline, not the 100 ms end. Every command prints the expected RTT for all six
# pairs and then MEASURES all twelve ordered pairs, so nobody has to hold that
# factor of two in their head — or trust it.
#
# Note `seq` is NOT used to walk NODES here: BSD seq counts DOWN when first > last
# (`seq 4 3` prints "4 3"), so the empty-range idiom that works under GNU seq walks
# off the end of the array on macOS. C-style loops instead.
NETEM_DEV=eth0

netem_qdisc() { dc exec -T "$1" tc qdisc show dev "$NETEM_DEV" 2>&1 | tr -d '\r' | tr '\n' ' '; }

# Print every node's qdisc verbatim, and return non-zero if ANY node disagrees with
# what was asked for.
#   netem_check_qdisc <d0,d1,d2,d3>   expect netem at that per-node delay
#   netem_check_qdisc ""              expect NO netem at all
netem_check_qdisc() {
  local want="$1" bad=0 q i n d
  local wants=()
  [[ -n "$want" ]] && { IFS=, read -r -a wants <<<"$want"; }
  echo "   -- tc qdisc show dev $NETEM_DEV, per container --"
  for (( i = 0; i < ${#NODES[@]}; i++ )); do
    n="${NODES[$i]}"
    q="$(netem_qdisc "$n")"
    printf '     %-6s %s\n' "$n" "${q:-<no output>}"
    if [[ -z "$want" ]]; then
      if grep -q 'netem' <<<"$q"; then
        echo "     ^ $n STILL carries a netem qdisc"; bad=1
      fi
    else
      d="${wants[$i]}"
      if ! grep -q 'netem' <<<"$q"; then
        echo "     ^ $n has NO netem qdisc"; bad=1
      elif ! grep -Eq "delay ${d}(\.0+)?ms" <<<"$q"; then
        echo "     ^ $n netem is present but its delay is not ${d}ms"; bad=1
      fi
    fi
  done
  return "$bad"
}

# The check that matters more than the qdisc: is the delay actually ON THE PATH?
# An installed qdisc on the wrong device, or on a device the container's traffic does
# not leave by, shows up green in `tc qdisc show` and changes nothing. Full 12-pair
# matrix, because a per-pair asymmetry would otherwise hide behind one node's average.
netem_rtt_matrix() {
  local out avg
  echo "   -- measured ICMP RTT, every ordered pair (5 pings, avg ms) --"
  for n in "${NODES[@]}"; do
    local row="     $n ->"
    for p in "${NODES[@]}"; do
      [[ "$n" == "$p" ]] && continue
      out="$(dc exec -T "$n" ping -q -c 5 -i 0.3 -W 5 "$p" 2>/dev/null || true)"
      avg="$(sed -n 's|.*= [0-9.]*/\([0-9.]*\)/.*|\1|p' <<<"$out" | tail -1)"
      row+=" $p=${avg:-FAIL}"
    done
    echo "$row"
  done
}

# ── CPU budget (issue #107 step 1d) ─────────────────────────────────────────
#
# The same verification discipline the netem commands use: what a node HAS is read
# back from inside the running container, never from the environment of whoever ran
# this script (that would only prove what was requested) and never from `docker
# inspect` alone (that reports the request too — it is the kernel's cgroup that
# decides). Both are printed, because a disagreement between them is a finding.
#
# A TRAP, found by testing rather than by reading the docs: `docker update --cpus 0
# --cpuset-cpus ""` exits 0 and prints the container name, and changes NOTHING.
# Docker reads 0 / "" as "leave this field alone", not as "remove the limit". So
# `cpu-budget none` RAISES the ceiling to the whole VM and says exactly that, rather
# than issuing a command that reads green and silently leaves the limit in place.

# Cores docker can see. Used to refuse a request the rig cannot honour, rather than
# letting the kernel silently clamp a cpuset and the run report a budget it never had.
vm_cores() { docker info --format '{{.NCPU}}' 2>/dev/null || echo 0; }

# WHICH CONTAINERS A CPU BUDGET APPLIES TO — the four nodes, plus `faucet` when it is
# actually running. This is the ONE place in this script where the faucet (#128) is not
# excluded, and the asymmetry is deliberate on both sides:
#
#   * It is excluded from `NODES` — and therefore from every scenario, telemetry
#     snapshot, netem matrix and advertise assertion — because it is a FIFTH node that
#     no T0 host corresponds to. Counting it as a T0 node would inflate every
#     four-node claim this harness makes.
#   * It is INCLUDED here because a CPU budget is a statement about the machine, not
#     about the topology. The faucet mines RandomX on the same synchronous main loop
#     the others do, so an unbudgeted faucet is an unlimited competitor for exactly
#     the cores a dedicated cpuset was meant to reserve. Budgeting the four and
#     leaving the fifth free does not measure a 2-vCPU host; it measures four
#     constrained nodes next to one that is not, which is a condition the T0 net has
#     no counterpart for and nobody would knowingly report.
#
# The four always come first and in NODES order, so their dedicated blocks are
# unchanged by whether the faucet is up (node0=0-1 … node3=6-7 at width 2, and the
# faucet takes 8-9). That keeps a with-faucet run comparable to a without-faucet one
# on the four nodes' own terms.
#
# `cid` (compose `ps -q`, which lists RUNNING services only) is empty for a faucet that
# is not up, which is how "is the faucet in this run" gets answered — from docker,
# rather than from an env var or an assumption about how the net was started.
#
# Callers read this with `targets=( $(cpu_targets) )` and NOT with `mapfile`/`readarray`:
# this script's shebang is `env bash` and macOS ships bash 3.2, which has neither. A
# `mapfile` here would abort the script on the rig it is most often run from, and the
# same reasoning is already recorded above for BSD `seq`. Container names are single
# words with no glob characters, so unquoted word-splitting is safe on them.
cpu_targets() {
  local t=("${NODES[@]}")
  [[ -n "$(cid faucet 2>/dev/null)" ]] && t+=(faucet)
  printf '%s\n' "${t[@]}"
}

# CPU budgets in HUNDREDTHS of a CPU, so the comparison is integer arithmetic and a
# fractional budget can be asserted exactly. "2" -> 200, "0.25" -> 25, "1.5" -> 150.
#
# Fractions are supported for one reason, and it is not convenience: measured on this
# harness (issue #107 step 1d) each node draws ~2.7 % of ONE core, so a 2-CPU budget is
# ~70x more than it asks for and `nr_throttled` stays 0 — the limit is installed and
# never binds. A budget BELOW measured demand is the positive control that shows the
# instrument can move the loop period at all, which is what makes a negative at the
# hosts' 2 vCPU worth anything. Such a budget is NOT a host model; label it as a
# control, never as "the hosts".
cpu_hundredths() {   # cpu_hundredths <n[.nn]>
  local v="$1" int frac
  int="${v%%.*}"
  if [[ "$v" == *.* ]]; then frac="${v#*.}"; else frac=""; fi
  frac="${frac}00"; frac="${frac:0:2}"
  echo $(( 10#${int:-0} * 100 + 10#${frac} ))
}

# node<idx>'s DEDICATED block of <width> cores: node0=0-1, node1=2-3, … for width 2.
# Distinct blocks are the point — four containers pinned to the same pair are a 4:1
# oversubscription of one pair, which is not what four 2-vCPU hosts are.
cpu_block() {   # cpu_block <width> <idx>
  local w="$1" i="$2" lo hi
  lo=$(( i * w )); hi=$(( lo + w - 1 ))
  echo "$lo-$hi"
}

# The kernel's view, from inside the container. `quota=max` means no quota at all.
cpu_cgroup() {   # cpu_cgroup <node>
  dc exec -T "$1" bash -c '
    read -r q p < /sys/fs/cgroup/cpu.max
    echo "quota=$q/$p cpuset=$(cat /sys/fs/cgroup/cpuset.cpus.effective) nproc=$(nproc)"
  ' 2>/dev/null | tr -d '\r' || echo "unreadable"
}

# The request, from the daemon. NanoCpus 0 / CpusetCpus "" = nothing was ever asked for.
cpu_inspect() {   # cpu_inspect <node>
  docker inspect -f 'NanoCpus={{.HostConfig.NanoCpus}} CpusetCpus="{{.HostConfig.CpusetCpus}}"' \
    "$(cid "$1")" 2>/dev/null || echo "uninspectable"
}

# DID THE LIMIT EVER ACTUALLY BIND? This is the question a CPU-scarcity run turns on,
# and it is not answerable from the limit itself — a quota that is never reached is
# installed, verified, and inert. `cpu.stat` answers it from the kernel's own counters:
#
#   nr_periods     enforcement windows elapsed (100 ms each)
#   nr_throttled   how many of them the cgroup was cut off in
#   throttled_usec total time spent cut off
#   usage_usec     CPU actually consumed — divide by nr_periods*100ms for the share
#
# nr_throttled = 0 means the budget was never the binding constraint, so any negative
# result from that run is a statement about the WORKLOAD's demand, not about scarcity.
# Say so when it happens rather than reporting the negative on its own.
cpu_throttle() {   # cpu_throttle <node>
  dc exec -T "$1" bash -c '
    awk "/^(nr_periods|nr_throttled|throttled_usec|usage_usec) /{printf \"%s=%s \", \$1, \$2}" \
      /sys/fs/cgroup/cpu.stat
    echo
  ' 2>/dev/null | tr -d '\r' || echo "unreadable"
}

# The CPU_BUDGET line the node printed AT STARTUP (entrypoint.sh). This is the budget
# the process booted under, which is not necessarily the one it has now — `cpu-budget`
# changes the cgroup live and cannot rewrite a log line already emitted. Comparing the
# two is how a reader tells "brought up under a limit" from "limited afterwards",
# and that distinction decides which samples belong to which condition.
cpu_startup_line() {   # cpu_startup_line <node>
  dc logs --no-log-prefix "$1" 2>/dev/null | grep '^CPU_BUDGET' | tail -1 || true
}

cpu_report() {   # cpu_report <label>
  local cores targets n; cores="$(vm_cores)"
  targets=( $(cpu_targets) )
  echo "== CPU budget: $1 =="
  echo "   docker sees $cores cores on this machine. The four T0 hosts have 2 vCPU EACH,"
  echo "   on four separate machines — this is one VM's scheduler either way."
  echo "   ${#targets[@]} containers in scope: ${targets[*]}"
  # `faucet` in that list is the FIFTH container, not a fifth T0 host — see
  # cpu_targets. It is budgeted because it mines and would otherwise compete for the
  # very cores a dedicated cpuset reserves; it is still excluded from every four-node
  # claim this harness makes.
  echo "   -- cgroup (the kernel's view, read inside each container) --"
  for n in "${targets[@]}"; do
    printf '     %-6s %s\n' "$n" "$(cpu_cgroup "$n")"
  done
  echo "   -- HostConfig (what was REQUESTED of the daemon) --"
  for n in "${targets[@]}"; do
    printf '     %-6s %s\n' "$n" "$(cpu_inspect "$n")"
  done
  echo "   -- did the budget ever BIND? (kernel throttling counters) --"
  for n in "${targets[@]}"; do
    printf '     %-6s %s\n' "$n" "$(cpu_throttle "$n")"
  done
  echo "   -- the budget each container BOOTED under (its own startup line) --"
  for n in "${targets[@]}"; do
    local sl; sl="$(cpu_startup_line "$n")"
    printf '     %-6s %s\n' "$n" "${sl:-<no CPU_BUDGET line: image predates issue #107 step 1d>}"
  done
}

# Assert every in-scope container's cgroup matches <want>, where want is a number of
# CPUs or the word `none`. Dies on the first mismatch: a run measured under a budget it
# cannot demonstrate is not evidence, and this is the check most worth not skipping.
cpu_check() {   # cpu_check <n|none>
  local want="$1" bad=0 targets
  targets=( $(cpu_targets) )
  echo "   -- asserting every container in scope (${targets[*]}) is at: $want --"
  for n in "${targets[@]}"; do
    local cg q; cg="$(cpu_cgroup "$n")"
    q="${cg#quota=}"; q="${q%%/*}"
    if [[ "$want" == "none" ]]; then
      # `none` after a `cpu-budget none` is a RAISED ceiling, not an absent one, so
      # accept either: no quota at all, or a quota >= every core on the machine.
      local period="${cg#*/}"; period="${period%% *}"
      if [[ "$q" == "max" ]]; then
        printf '     %-6s ok  (no quota at all)\n' "$n"
      elif [[ "$q" =~ ^[0-9]+$ && "$period" =~ ^[0-9]+$ ]] \
        && (( q / period >= $(vm_cores) )); then
        printf '     %-6s ok  (quota >= the whole machine: %s)\n' "$n" "$cg"
      else
        printf '     %-6s MISMATCH: %s\n' "$n" "$cg"; bad=1
      fi
    else
      local period="${cg#*/}"; period="${period%% *}"
      # Integer comparison in hundredths of a CPU, so 0.25 asserts as exactly as 2 does.
      if [[ "$q" =~ ^[0-9]+$ && "$period" =~ ^[1-9][0-9]*$ ]] \
        && (( q * 100 / period == $(cpu_hundredths "$want") )); then
        printf '     %-6s ok  (%s)\n' "$n" "$cg"
      else
        printf '     %-6s MISMATCH (wanted quota %s CPU): %s\n' "$n" "$want" "$cg"; bad=1
      fi
    fi
  done
  (( bad == 0 )) || die "the CPU budget is not what was requested on at least one
   container. Do NOT report numbers from this net — the condition is not established.
   If the nodes were brought up from an image that predates issue #107 step 1d they will
   still be limited correctly (the limit is the daemon's, not the image's), but they
   will print no CPU_BUDGET startup line, so the run's own record will not carry it.
   If the MISMATCH is on \`faucet\` alone, the likely cause is that it was started
   after \`cpu-budget\` ran — the budget is applied to what is up at the time, so
   re-run \`cpu-budget\` (or set FAUCET_CPUS/FAUCET_CPUSET on the compose service)."
  echo "   ✓ every in-scope container's cgroup matches what was requested"
}

netem_report() {   # netem_report <d0,d1,d2,d3|""> <label>
  local want="$1" label="$2" i j
  local wants=()
  echo "== netem: $label =="
  if [[ -n "$want" ]]; then
    IFS=, read -r -a wants <<<"$want"
    echo "   expected pairwise RTT = one-way(A) + one-way(B):"
    for (( i = 0; i < ${#NODES[@]}; i++ )); do
      for (( j = i + 1; j < ${#NODES[@]}; j++ )); do
        printf '     %s<->%s  %sms + %sms = ~%sms\n' \
          "${NODES[$i]}" "${NODES[$j]}" "${wants[$i]}" "${wants[$j]}" \
          "$(( wants[i] + wants[j] ))"
      done
    done
  fi
  netem_check_qdisc "$want" \
    || die "the qdisc is NOT what was asked for (above). A run under a silently-absent
   netem produces a clean, confident answer that means nothing. STOP."
  echo "   ✓ every node's qdisc matches what was requested"
  netem_rtt_matrix
}

# ── advertised-address mode (issue #107 step 1c) ─────────────────────────────
#
# Which mode a node is in is NOT read from the environment of whoever runs this
# script — that would only prove what was requested. It is read back from the running
# container, two independent ways, the same discipline the netem commands use:
#
#   (1) the generated /tmp/node.toml: does an `advertise_addr =` key exist at all
#   (2) the node's OWN startup output: the binary prints "no advertise_addr: ..."
#       (qumbra-node/src/run.rs) when the field is missing, so mode `none` is
#       confirmed by the code under test rather than by the file we wrote for it
#
# A disagreement between (1) and (2) means the running process is not using the
# config file we are reading, which is a reason to stop rather than to interpret.
advertise_mode_of() {
  local n="$1" toml=""
  # `|| true`: a stopped node makes exec fail, which would abort under pipefail.
  toml="$(dc exec -T "$n" sh -c 'grep -c "^advertise_addr[[:space:]]*=" /tmp/node.toml || true' 2>/dev/null | tr -d '\r' | tail -1)"
  case "$toml" in
    0) echo none ;;
    ''|*[!0-9]*) echo unknown ;;
    *) echo auto ;;
  esac
}

# Did the node itself say it has no advertised address? (Absence of this line is only
# evidence when the node has produced output at all, so report the two apart.)
#
# `grep -c`, never `grep -q`, and the reason is not style: -q exits on the FIRST match,
# which SIGPIPEs `docker compose logs`, and under `set -o pipefail` the pipeline then
# reports 141 — so a matched line reads as "no match" whenever the log is long enough
# that the writer is still going. That inverts this answer on exactly the nodes that
# have been running longest, and it is a race, so it passes on a short log.
advertise_node_said_none() {
  local hits
  hits="$(dc logs --no-log-prefix "$1" 2>/dev/null | grep -c 'no advertise_addr:' || true)"
  [[ "${hits:-0}" -gt 0 ]] && echo yes || echo no
}

# Print each node's mode; with an expected mode, assert it. Fatal on a disagreement
# between the two readbacks (always) or on a mode that is not the expected one; a
# node that is simply down is reported, not fatal — the partition and committee
# scenarios stop nodes on purpose.
advertise_show() {
  local want="${1:-}" n mode said inconsistent=0 wrong=0 down=0 line dial prs
  echo "   -- advertised-address mode, read back per container --"
  for n in "${NODES[@]}"; do
    mode="$(advertise_mode_of "$n")"
    said="$(advertise_node_said_none "$n")"
    line="$(latest "$n")"
    dial="$(field "$line" dialable)"; prs="$(field "$line" peers)"
    printf '     %-6s node.toml=%-7s binary-said-none=%-3s dialable=%-5s peers=%s\n' \
      "$n" "$mode" "$said" "${dial:-?}" "${prs:-?}"
    if [[ "$mode" == unknown ]]; then
      echo "     ^ $n did not answer (down, or no /tmp/node.toml) — mode unread"
      down=1
    elif [[ "$mode" == none && "$said" == no ]]; then
      echo "     ^ $n has no advertise_addr in its config but never printed the"
      echo "       'no advertise_addr' line — the process may not be using this file."
      inconsistent=1
    elif [[ "$mode" == auto && "$said" == yes ]]; then
      echo "     ^ $n HAS an advertise_addr but printed 'no advertise_addr' — same"
      echo "       problem from the other direction."
      inconsistent=1
    fi
    if [[ -n "$want" && "$mode" != unknown && "$mode" != "$want" ]]; then
      echo "     ^ $n is in mode '$mode', expected '$want'"; wrong=1
    fi
  done
  (( inconsistent )) && die "a node's config file and its own output disagree about the
   advertised address. The running process may not be reading the file this check
   reads. STOP — do not attribute this run to either condition."
  (( wrong )) && die "advertised-address mode is not '$want' on every node — do not
   attribute this run to either condition until that is resolved."
  if [[ -n "$want" ]]; then
    (( down )) && { echo "   (partial) every node that answered is in mode '$want'"; return 0; }
    echo "   ✓ every node is in advertise mode '$want'"
  fi
  return 0
}

# Wait until a node's tip reaches at least H (or timeout secs). Returns 0/1.
wait_tip() {
  local node="$1" want="$2" timeout="${3:-300}" waited=0
  while (( waited < timeout )); do
    local line tip; line="$(latest "$node")"; tip="$(field "$line" tip)"
    [[ -n "$tip" ]] && (( tip >= want )) && return 0
    sleep 5; waited=$((waited + 5))
  done
  return 1
}

# Assert every named node is halted at the boundary, with an IDENTICAL finalized
# tip. Any disagreement here is a stop-point, not a retry.
halt_assert_halted() {
  local ref_tip="" ref_final=""
  for n in "$@"; do
    local line; line="$(latest "$n")"
    [[ -n "$line" ]] || die "$n produced no telemetry — capture logs, STOP"
    local tip final regime halt
    tip="$(field "$line" tip)"; final="$(field "$line" final)"
    regime="$(field "$line" regime)"; halt="$(field "$line" halt)"
    [[ "$halt" == "$HALT_H" ]] || die "$n reports halt=$halt, expected $HALT_H — wrong binary? STOP."
    [[ "$tip" == "$HALT_H" ]]       || die "$n tip=$tip but the halt height is $HALT_H — an armed node must not pass it. STOP."
    [[ "$regime" == "Halted" ]]       || die "$n regime=$regime, expected Halted. If it is 'Halting', H's checkpoint has not
   finalized — that is the honest signal NOT to swap binaries yet. Wait, then re-check."
    if [[ -z "$ref_tip" ]]; then ref_tip="$tip"; ref_final="$final"; fi
    [[ "$tip" == "$ref_tip" && "$final" == "$ref_final" ]]       || die "$n disagrees about the boundary (tip=$tip final=$final vs $ref_tip/$ref_final). STOP."
  done
  echo "   ✓ all armed nodes report regime=Halted at an IDENTICAL finalized tip $ref_tip/$ref_final"
}

# The invariant the whole mechanism exists to protect: no two nodes may report
# different finalized blocks at the same height.
#
# UNTIL 2026-07-29 this was checked by proxy, because telemetry carried heights and
# no hashes — two nodes finalizing DIFFERENT checkpoints at the same height printed
# identical lines. Issue #84 put the finalized checkpoint's identity on the line
# (`fid`), so the condition is now expressible directly and this checks it directly.
# The height-based guard below is kept: it catches a reorg past finality, which is a
# different failure and still worth its own assertion.
halt_assert_no_conflicting_finality() {
  local upgraded=(node0 node1 node2)
  local ref=""
  for n in "${upgraded[@]}"; do
    local f; f="$(field "$(latest "$n")" final)"
    [[ -n "$f" && "$f" != "-" ]] || continue
    if [[ -z "$ref" ]]; then ref="$f"; continue; fi
    local lo=$(( f < ref ? f : ref ))
    (( lo >= HALT_H )) || die "an upgraded node finalized BELOW the boundary — reorg past
   finality. STOP EVERYTHING and preserve state."
  done
  echo "   ✓ no upgraded node finalized below the boundary (no reorg past a finalized checkpoint)"

  # THE CONDITION THIS FUNCTION IS NAMED AFTER. Same finalized height, different
  # identity, on two nodes = two checkpoints finalized at one height. That is the
  # most severe STOP-POINT this project has, and before #84 it was invisible.
  local i j missing=0 checked=0
  for (( i = 0; i < ${#upgraded[@]}; i++ )); do
    local ni="${upgraded[$i]}" li fi_h fi_d
    li="$(latest "$ni")"; fi_h="$(field "$li" final)"; fi_d="$(field "$li" fid)"
    [[ -n "$fi_h" && "$fi_h" != "-" ]] || continue
    if [[ -z "$fi_d" ]]; then missing=1; continue; fi
    for (( j = i + 1; j < ${#upgraded[@]}; j++ )); do
      local nj="${upgraded[$j]}" lj fj_h fj_d
      lj="$(latest "$nj")"; fj_h="$(field "$lj" final)"; fj_d="$(field "$lj" fid)"
      [[ -n "$fj_h" && "$fj_h" != "-" ]] || continue
      if [[ -z "$fj_d" ]]; then missing=1; continue; fi
      [[ "$fi_h" == "$fj_h" ]] || continue
      checked=$(( checked + 1 ))
      [[ "$fi_d" == "$fj_d" ]] || die "TWO DIFFERENT CHECKPOINTS FINALIZED AT HEIGHT $fi_h —
   $ni fid=$fi_d vs $nj fid=$fj_d. This is the R2 STOP-POINT. STOP EVERYTHING,
   preserve every container's logs and /opt/qumbra/data before touching anything."
    done
  done

  # An image without #84 prints no `fid`. Say that the check did not run rather than
  # printing a tick — a silent pass here is exactly the failure this whole comment
  # block exists to describe, arriving from the other direction.
  if (( missing == 1 )); then
    echo "   (finding) at least one node prints no fid= — this image predates issue #84,"
    echo "             so the same-height/different-identity check DID NOT RUN. Heights"
    echo "             agreeing is not evidence that the checkpoints agree."
  elif (( checked == 0 )); then
    echo "   (finding) no two upgraded nodes shared a finalized height at this sample, so"
    echo "             there was nothing to compare. Not a pass — re-sample."
  else
    echo "   ✓ every pair at a shared finalized height reports the same fid ($checked pair(s))"
  fi
}

# What this node's OWN keys signed, which is a different question from what it
# finalized — and the one that catches a split the finalized view cannot see.
#
# Observed live on 2026-07-29 at slot 3776: sixteen keys signed one variant and five
# signed another, yet all four nodes finalized the SAME checkpoint, because the
# minority finalizes the majority's. `fid` was identical everywhere; only `sid`
# differed. So a divergence here is NOT a stop condition — it is the normal cost of
# signing when the tip first touches a slot, and it is reported as a finding.
halt_report_signed_divergence() {
  local nodes=("$@") i j split=0 missing=0
  for (( i = 0; i < ${#nodes[@]}; i++ )); do
    local ni="${nodes[$i]}" li si_s si_d
    li="$(latest "$ni")"; si_s="$(field "$li" sslot)"; si_d="$(field "$li" sid)"
    if [[ -z "$si_s" || -z "$si_d" ]]; then missing=1; continue; fi
    [[ "$si_d" != "-" ]] || continue
    for (( j = i + 1; j < ${#nodes[@]}; j++ )); do
      local nj="${nodes[$j]}" lj sj_s sj_d
      lj="$(latest "$nj")"; sj_s="$(field "$lj" sslot)"; sj_d="$(field "$lj" sid)"
      [[ -n "$sj_s" && -n "$sj_d" && "$sj_d" != "-" ]] || continue
      [[ "$si_s" == "$sj_s" ]] || continue
      if [[ "$si_d" != "$sj_d" ]]; then
        split=1
        echo "   (finding) signed-variant split at slot $si_s: $ni sid=$si_d vs $nj sid=$sj_d"
      fi
    done
  done
  if (( missing == 1 )); then
    echo "   (finding) at least one node prints no sslot=/sid= — image predates issue #84;"
    echo "             the signed-variant check did not run."
  elif (( split == 0 )); then
    echo "   ✓ no signed-variant split among the sampled nodes"
  else
    echo "             ^ not a stop condition. Record it; it is the per-key burn shape."
  fi
}

# WHICH LAYER refused an old-binary block (issue #74). The two counters are on
# every telemetry line and mean different things about the upgrade:
#   hignore — this release is HALTED and did not act on the block. The block was not
#             judged invalid and the sender is NOT penalised (release layer).
#   powrej  — the header failed the PoW target. Above an upgrade boundary that is the
#             post-halt rule domain biting: the block is invalid on the upgraded net
#             and never reaches fork choice (header-validation layer).
# §4 as written describes the second kind of outcome. Report what the logs actually
# show; do NOT paraphrase one as the other.
# Where the drill parks its evidence. The counters are PER-PROCESS and reset when a
# container is recreated (which a binary swap necessarily does), so the before/after
# pair has to be captured to disk — a post-swap process legitimately reports
# hignore=0 because it is a new process, not because nothing was ignored.
EVID_DIR="$SCRIPT_DIR/../../docs"
EVID="$EVID_DIR/m11-halt-height-evidence.log"

# Append a labelled snapshot of every node's raw telemetry line to the evidence log.
halt_record() {
  local label="$1"
  { echo "=== $label ==="
    for n in "${NODES[@]}"; do printf '%s %s\n' "$n" "$(latest "$n")"; done
  } >> "$EVID"
  echo "   (evidence appended: $label → ${EVID#"$SCRIPT_DIR/../../"})"
}

# Save the pre-swap counter values so the post-swap comparison is against a real
# recorded number rather than a remembered one.
halt_save_counters() {
  : > "$SCRIPT_DIR/.halt-preswap"
  for n in "${NODES[@]}"; do
    local line; line="$(latest "$n")"
    printf '%s %s %s\n' "$n" "$(field "$line" hignore)" "$(field "$line" powrej)" \
      >> "$SCRIPT_DIR/.halt-preswap"
  done
}
halt_preswap() {  # halt_preswap <node> <hignore|powrej>
  local n="$1" which="$2"
  local col=2; [[ "$which" == "powrej" ]] && col=3
  awk -v n="$n" -v c="$col" '$1 == n { print $c }' "$SCRIPT_DIR/.halt-preswap" 2>/dev/null
}

# Normalise a telemetry `final=` field to an integer; `-` (nothing finalized) → -1.
fin_num() { local v="$1"; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo "-1"; }

# DRILL (a)'s real assertion: while the checkpointed branch keeps finalizing, the
# un-upgraded node's finality must STOP advancing.
#
# Early after the swap node3 can legitimately still be tracking the checkpointed
# branch's checkpoints (that is what `final=24, tip=23` was), so a single window in
# which node3 also advances is NOT a failure — it is an inconclusive window. Only a
# node3 that keeps pace across repeated windows would contradict §4. Being wrong in
# the other direction is how the original check earned a false STOP-POINT; this one
# reports "not demonstrated" rather than inventing a violation.
halt_assert_old_branch_finality_frozen() {
  local rounds=3 r win=1500
  for (( r = 1; r <= rounds; r++ )); do
    local f0a f3a; f0a="$(fin_num "$(field "$(latest node0)" final)")"
    f3a="$(fin_num "$(field "$(latest node3)" final)")"
    echo "   -- window $r/$rounds: waiting for the CHECKPOINTED branch to finalize again"
    echo "      (start: node0 final=$f0a · node3 final=$f3a)"
    local waited=0 f0b=$f0a
    while (( waited < win )); do
      f0b="$(fin_num "$(field "$(latest node0)" final)")"
      (( f0b > f0a )) && break
      sleep 15; waited=$((waited + 15))
    done
    if (( f0b <= f0a )); then
      echo "   (finding) the CHECKPOINTED branch did not finalize again within ${win}s"
      echo "             (node0 final stuck at $f0a). That is a finding about the upgraded"
      echo "             net, NOT about node3 — drill (a)'s freeze claim is untested here."
      return 0
    fi
    local f3b; f3b="$(fin_num "$(field "$(latest node3)" final)")"
    echo "      (end:   node0 final=$f0b · node3 final=$f3b)"
    if (( f3b == f3a )); then
      echo "   ✓ the old-binary branch's finality is FROZEN at $f3b while the checkpointed"
      echo "     branch advanced $f0a → $f0b. Its blocks can never finalize (§4)."
      # `final > tip` on the un-upgraded node is EXPECTED here — it tracked the
      # upgraded branch's checkpoint for a block it does not hold. Named so a reader
      # does not have to rediscover it; see issue #85.
      local t3; t3="$(field "$(latest node3)" tip)"
      if [[ "$t3" =~ ^[0-9]+$ ]] && (( f3b > t3 )); then
        echo "     note: node3 reports final=$f3b > tip=$t3. EXPECTED here — it finalized the"
        echo "           UPGRADED branch's checkpoint for a block it does not hold. Its"
        echo "           ChainState is untouched (set_finalized fails on an unknown block)."
        echo "           This is issue #85, not a fault of this drill."
      fi
      return 0
    fi
    echo "      node3 also advanced ($f3a → $f3b) — it is still TRACKING the checkpointed"
    echo "      branch (expected while the branches are inside the tally window). Not a"
    echo "      violation; retrying with a fresh window."
  done
  echo "   (finding) node3's finality kept pace across $rounds windows, so the freeze was"
  echo "             NOT demonstrated. This is NOT by itself a two-branch finalization —"
  echo "             telemetry cannot distinguish 'finalized the same checkpoint' from"
  echo "             'finalized a different one' (issue #84). Do not read it either way:"
  echo "             capture 'dc logs' for all four nodes and settle it by inspection."
}

halt_report_layers() {
  echo "   -- refusal layers (hignore = release layer · powrej = header-validation layer) --"
  for n in "${NODES[@]}"; do
    local line; line="$(latest "$n")"
    [[ -n "$line" ]] || continue
    printf '     %-6s hignore=%-5s powrej=%-5s   %s\n' \
      "$n" "$(field "$line" hignore)" "$(field "$line" powrej)" \
      "$(field "$line" regime)"
  done
  echo "     (raw rejection reasons: dc logs <node> | grep -E 'above halt height|invalid header')"
}

cmd="${1:-}"; shift || true
case "$cmd" in

  rehearsal)
    guard_rig
    echo "== genesis rehearsal =="
    echo "-- building image (first Linux build of randomx-rs + qumbra-node) --"
    dc build
    echo "-- starting all 4 nodes (genesis-init runs first via depends_on) --"
    dc up -d node0 node1 node2 node3
    # genesis-init has exited (service_completed_successfully); read the hash it
    # printed ("init: genesis hash <hash>") from its captured logs.
    got="$(dc logs --no-log-prefix genesis-init 2>/dev/null \
            | sed -n 's/^init: genesis hash //p' | tail -1 | tr -d '\r')"
    echo "   in-container genesis hash: ${got:-<unread>}"
    echo "   pinned T0 genesis hash:    $PINNED_GENESIS"
    [[ "$got" == "$PINNED_GENESIS" ]] \
      || die "GENESIS HASH MISMATCH — in-container genesis is not the frozen T0 genesis. STOP."
    # Derived from $PINNED_GENESIS, never re-typed — the hardcoded literal that
    # used to live here went stale twice (#101, #115) while the check above passed.
    echo "   ✓ in-container genesis == pinned T0 genesis (${PINNED_GENESIS:0:8}…${PINNED_GENESIS: -4})"
    # Which advertised-address condition this net came up in, in the net's own output
    # (issue #107 step 1c). Asserted when the caller named a mode, printed either way:
    # a per-node NODE<i>_ADVERTISE override means the global env is not authoritative,
    # so the readback is, and it is what gets printed.
    advertise_show "${QUMBRA_ADVERTISE_ADDR:-}" || true
    echo "   nodes up; watch blocks with: $0 sample 200"
    ;;

  status)  snapshot ;;

  advertise-show)
    want="${1:-}"
    [[ -z "$want" || "$want" == auto || "$want" == none ]] \
      || die "advertise-show takes 'auto', 'none', or nothing (got '$want')"
    advertise_show "$want"
    ;;

  sample)
    secs="${1:-180}"; ivl="${2:-30}"; waited=0
    while (( waited <= secs )); do
      echo "== t+${waited}s =="; snapshot; echo
      sleep "$ivl"; waited=$((waited + ivl))
    done
    ;;

  # ── latency injection (issue #107 step 1b) ────────────────────────────────

  netem)
    arg="${1:?netem needs a ONE-WAY delay in ms: 'netem 100' (uniform) or 'netem 30,60,90,110' (per node)}"
    jit="${2:-0}"
    [[ "$jit" =~ ^[0-9]+$ ]] || die "jitter must be a whole number of ms, got '$jit'"
    IFS=, read -r -a delays <<<"$arg"
    # A bare number means the same delay everywhere; four means one per node, in
    # NODES order. Per-node delays are how the real topology's ASYMMETRY is modelled:
    # node_i -> node_j pays delay_i and the reply pays delay_j, so each pair gets its
    # own RTT and each direction its own one-way — which uniform delay cannot express.
    if [[ "${#delays[@]}" -eq 1 ]]; then
      for (( i = 1; i < ${#NODES[@]}; i++ )); do delays[$i]="${delays[0]}"; done
    elif [[ "${#delays[@]}" -ne "${#NODES[@]}" ]]; then
      die "netem takes 1 delay (uniform) or ${#NODES[@]} (one per node), got ${#delays[@]}"
    fi
    want=""
    for (( i = 0; i < ${#NODES[@]}; i++ )); do
      n="${NODES[$i]}"; d="${delays[$i]}"
      [[ "$d" =~ ^[0-9]+$ ]] || die "delay must be a whole number of ms, got '$d'"
      spec="delay ${d}ms"
      (( jit > 0 )) && spec="delay ${d}ms ${jit}ms distribution normal"
      # `replace` rather than `add`: idempotent, so re-running at a new delay does not
      # need a clear first and cannot leave two runs' qdiscs stacked.
      dc exec -T "$n" tc qdisc replace dev "$NETEM_DEV" root netem $spec \
        || die "tc failed on $n. Is NET_ADMIN granted (docker-compose.yml cap_add) and
   is this image new enough to carry iproute2 (Dockerfile)? A net brought up from an
   older image has neither, and every command here would then be a no-op."
      echo "   applied on $n: netem $spec"
      want+="${d},"
    done
    want="${want%,}"
    netem_report "$want" "applied (one-way ${arg}ms, jitter ${jit}ms)"
    echo
    echo "   The nodes were NOT restarted, so existing TCP connections keep running;"
    echo "   the delay applies from now on. Give the net a few telemetry cadences"
    echo "   before you start the window you intend to report."
    ;;

  cpu-budget)
    arg="${1:?cpu-budget needs a number of CPUs per container (2, 1.5, 0.25 — fractions are the positive control), or 'none' to raise the ceiling back}"
    mode="${2:-dedicated}"
    [[ "$mode" == dedicated || "$mode" == quota-only ]] \
      || die "cpu-budget's second argument is 'dedicated' (default) or 'quota-only', got '$mode'"
    if [[ "$arg" == none ]]; then
      cores="$(vm_cores)"
      (( cores > 0 )) || die "could not read the machine's core count from docker info"
      # NOT a clear — see the trap note above `vm_cores`. Raise quota to every core and
      # widen the cpuset to all of them, which is the largest budget a container on this
      # machine could ever use, and label it honestly.
      targets=( $(cpu_targets) )
      for n in "${targets[@]}"; do
        docker update --cpus "$cores" --cpuset-cpus "0-$(( cores - 1 ))" "$(cid "$n")" >/dev/null \
          || die "docker update failed on $n"
        echo "   raised on $n: quota $cores CPU, cpuset 0-$(( cores - 1 ))"
      done
      cpu_report "raised to the whole machine ($cores cores)"
      cpu_check none
      echo
      echo "   This is EFFECTIVELY unconstrained, not literally unconstrained: the"
      echo "   container still carries a quota (of every core there is) and a cpuset (of"
      echo "   all of them). \`docker update --cpus 0\` is a silent no-op, so there is no"
      echo "   way to remove them from a running container — only a fresh \`up\` with the"
      echo "   compose defaults gives NanoCpus=0. Report this condition as 'quota raised"
      echo "   to $cores CPU', and note that these containers' CPU_BUDGET startup lines"
      echo "   still show whatever they booted with."
      exit 0
    fi
    [[ "$arg" =~ ^[0-9]+(\.[0-9]+)?$ ]] && (( $(cpu_hundredths "$arg") > 0 )) \
      || die "cpu-budget takes a positive number of CPUs (2, 0.5, 0.25), got '$arg'"
    cores="$(vm_cores)"
    # A dedicated block is whole cores — you cannot pin half a core — so a fractional
    # budget still gets one core of affinity and the quota does the limiting.
    width=$(( ( $(cpu_hundredths "$arg") + 99 ) / 100 ))
    (( width >= 1 )) || width=1
    # The four nodes, plus the faucet when it is up — see cpu_targets for why the CPU
    # budget is the one axis the fifth container is NOT excluded from. NODES order is
    # preserved and the faucet is appended last, so node0..node3 keep the same blocks
    # whether or not the faucet is in the run.
    targets=( $(cpu_targets) )
    if [[ "$mode" == dedicated ]]; then
      need=$(( width * ${#targets[@]} ))
      (( cores >= need )) || die "a dedicated $width-core block for each of ${#targets[@]} containers
   (${targets[*]}) needs $need cores; docker reports only $cores on this machine.
   Either lower the budget, or stop the faucet if it is in the list and the run does
   not need it, or use 'cpu-budget $arg quota-only', which does not pin cores — but say
   which you used, because sharing cores between the containers is a different
   experiment."
    fi
    for (( i = 0; i < ${#targets[@]}; i++ )); do
      n="${targets[$i]}"
      if [[ "$mode" == dedicated ]]; then
        blk="$(cpu_block "$width" "$i")"
        docker update --cpus "$arg" --cpuset-cpus "$blk" "$(cid "$n")" >/dev/null \
          || die "docker update failed on $n (is the net up?)"
        echo "   applied on $n: quota $arg CPU, dedicated cores $blk"
      else
        docker update --cpus "$arg" "$(cid "$n")" >/dev/null \
          || die "docker update failed on $n (is the net up?)"
        echo "   applied on $n: quota $arg CPU, cores NOT pinned (nproc stays at $cores)"
      fi
    done
    cpu_report "applied live: $arg CPU per container ($mode)"
    cpu_check "$arg"
    echo
    echo "   The containers were NOT restarted, so this is the same processes, the same"
    echo "   tip range and the same build as before the change — which is the point. Their"
    echo "   CPU_BUDGET startup lines still report the budget they BOOTED with, so read"
    echo "   the cgroup block above, not the startup block, for the current condition."
    echo "   Give the net a few telemetry cadences before starting the window you report."
    ;;

  cpu-show)
    # Reports; asserts only if told what to expect. Run with no argument when you do
    # not already know what is installed — "unconstrained" is an answer here, not a
    # failure — and with an argument when a condition has to be established before
    # numbers from it may be quoted.
    cpu_report "current state"
    if [[ -n "${1:-}" ]]; then
      cpu_check "$1"
    else
      echo "   (no expectation given — nothing asserted. Pass '2' or 'none' to assert.)"
    fi
    ;;

  netem-show)
    # Reports, never asserts: this is the command you run when you do not already know
    # what is installed, so "no netem" is an answer here rather than a failure.
    echo "== netem: current state =="
    any=0
    echo "   -- tc qdisc show dev $NETEM_DEV, per container --"
    for n in "${NODES[@]}"; do
      q="$(netem_qdisc "$n")"
      printf '     %-6s %s\n' "$n" "${q:-<no output>}"
      grep -q 'netem' <<<"$q" && any=1
    done
    if (( any == 0 )); then
      echo "   => no netem qdisc on any node: this is a ZERO-LATENCY run."
    else
      echo "   => netem is installed. The figure above is ONE-WAY; RTT is ~twice it."
    fi
    netem_rtt_matrix
    ;;

  netem-clear)
    for n in "${NODES[@]}"; do
      # `|| true`: deleting a root qdisc that was never added is not an error worth
      # aborting on — the post-condition below is what decides whether this worked.
      dc exec -T "$n" tc qdisc del dev "$NETEM_DEV" root 2>/dev/null || true
      echo "   cleared on $n"
    done
    netem_report "" "cleared"
    ;;

  latejoiner)
    echo "== late-joiner sync-from-genesis (node3) =="
    # True from-genesis join: wipe node3's DATA IN PLACE (not the volume/container),
    # then `dc start` — reusing the existing container keeps its network endpoint
    # stable, so its one-shot startup dials resolve node0..2 (recreating the
    # container recreates the network and the dials fire during the blip → they
    # fail with no re-dial; that is finding #F-dial in the run doc).
    dc stop node3 2>/dev/null || true
    docker run --rm -v qumbra-t0-lite_data3:/d alpine sh -c 'rm -rf /d/* /d/..?* 2>/dev/null || true'
    echo "-- node3 stopped + data wiped in place; letting node0..2 advance --"
    wait_tip node0 5 400 || echo "   (warn) node0 did not reach tip 5 in time"
    echo "   before join:"; snapshot
    echo "-- starting node3 fresh (must sync from genesis) --"
    dc start node3
    lead="$(field "$(latest node0)" tip)"; lead="${lead:-5}"
    if wait_tip node3 "$lead" 400; then
      echo "   ✓ node3 synced to tip >= $lead"
    else
      echo "   (finding) node3 did not catch up to $lead within 400s — capture logs"
    fi
    snapshot
    ;;

  restart)
    node="${1:?restart needs a node name (e.g. node1)}"
    echo "== mining-node restart: $node (open==replay on its volume) =="
    before="$(field "$(latest "$node")" tip)"
    echo "   tip before stop: ${before:-?}"
    dc stop "$node"
    sleep 3
    dc start "$node"
    sleep 8
    after="$(field "$(latest "$node")" tip)"
    echo "   tip after restart: ${after:-?}"
    if [[ -n "$before" && -n "$after" ]] && (( after >= before )); then
      echo "   ✓ open==replay: tip persisted (>= pre-restart height) from the disk log"
    else
      echo "   (finding) tip did not persist across restart — inspect the block log"
    fi
    ;;

  partition)
    echo "== 2+2 partition (A={node0,node1} 11 keys | B={node2,node3} 10 keys) =="
    echo "   both sides < 15 quorum ⇒ finality MUST stall on both sides (expected, not a bug)"
    docker network inspect "$NET_SIDEB" >/dev/null 2>&1 || docker network create "$NET_SIDEB" >/dev/null
    # keep the B-side pair talking to each other over sideb, then cut them off qumbra
    docker network connect "$NET_SIDEB" "$(cid node2)"
    docker network connect "$NET_SIDEB" "$(cid node3)"
    docker network disconnect "$NET_MAIN" "$(cid node2)"
    docker network disconnect "$NET_MAIN" "$(cid node3)"
    echo "   partitioned. sample both sides:"; snapshot
    echo "   watch finality: stall should GROW and regime flip to Degraded on both sides"
    ;;

  heal)
    echo "== heal the partition =="
    docker network connect "$NET_MAIN" "$(cid node2)" || true
    docker network connect "$NET_MAIN" "$(cid node3)" || true
    docker network disconnect "$NET_SIDEB" "$(cid node2)" 2>/dev/null || true
    docker network disconnect "$NET_SIDEB" "$(cid node3)" 2>/dev/null || true
    echo "   reconnected to $NET_MAIN. periodic re-dial (M10-T0-5 / S9) reconnects the split"
    echo "   peers WITHOUT a restart; fork-choice converges and cross-node vote aggregation"
    echo "   resumes → finality (final=) should advance again on both sides within ~1–2 cadences."
    snapshot
    ;;

  committee-stall)
    echo "== committee stall: stop node1+node2+node3 (16 keys offline; node0's 6 < 15) =="
    dc stop node1 node2 node3
    echo "   node0 keeps mining (PoW) but cannot finalize — regime → Degraded, stall grows."
    snapshot
    ;;

  committee-recover)
    echo "== T0-2 recovery: restart the finalizers → committee re-forms → catch-up =="
    dc start node1 node2 node3
    echo "   21 keys reachable again; checkpoints should resume and finalize the backlog."
    snapshot
    ;;


  # ── halt-height upgrade drill (issue #74) ─────────────────────────────────
  #
  # H is the DRILL_HALT_HEIGHT compiled into the drill binaries
  # (crates/qumbra-node/src/release.rs). Keep these in step.

  halt-status)
    echo "== halt view =="
    for n in "${NODES[@]}"; do
      line="$(latest "$n")"
      if [[ -z "$line" ]]; then
        printf '  %-6s (no telemetry yet / down)\n' "$n"
      else
        printf '  %-6s tip=%-4s final=%-4s regime=%-8s halt=%-4s hignore=%-4s powrej=%-4s peers=%s\n' \
          "$n" "$(field "$line" tip)" "$(field "$line" final)" \
          "$(field "$line" regime)" "$(field "$line" halt)" \
          "$(field "$line" hignore)" "$(field "$line" powrej)" "$(field "$line" peers)"
      fi
    done
    ;;

  halt-arm)
    guard_rig
    echo "== halt-height drill, phase 1: ARM =="
    echo "   node0/1/2 → qumbra-node-armed (halts at H=$HALT_H)"
    echo "   node3     → qumbra-node        (the §4 old-binary miner: it never"
    echo "               deployed the halt, so it will keep mining past H)"
    echo "   Destroying any previous net so the drill starts from genesis."
    dc down -v >/dev/null 2>&1 || true
    docker network rm "$NET_SIDEB" 2>/dev/null || true
    dc build
    # Sample every 5 s for the arming phase: `regime=Halting` is a real but SHORT
    # interval (tip reaches H, then the 6/5/5/5 vote round closes), and at the 30 s
    # default it can open and close between two prints. Observability only.
    NODE0_BIN=qumbra-node-armed NODE1_BIN=qumbra-node-armed \
    NODE2_BIN=qumbra-node-armed NODE3_BIN=qumbra-node QUMBRA_SAMPLE_SECS=5 \
      dc up -d node0 node1 node2 node3
    got="$(dc logs --no-log-prefix genesis-init 2>/dev/null \
            | sed -n 's/^init: genesis hash //p' | tail -1 | tr -d '\r')"
    [[ "$got" == "$PINNED_GENESIS" ]] \
      || die "GENESIS HASH MISMATCH — the drill must run on the frozen T0 genesis. STOP."
    echo "   ✓ genesis == pinned T0 genesis; the drill changes NO frozen value (H5)"
    echo "   waiting for tip $HALT_H (75 s blocks — roughly $((HALT_H * 75 / 60)) min)…"
    wait_tip node0 "$HALT_H" 2400 || die "node0 never reached H=$HALT_H — capture logs, STOP"
    sleep 90   # let H's checkpoint finalize and telemetry catch up
    "$0" halt-status
    halt_assert_halted node0 node1 node2
    halt_report_layers
    halt_record "phase 1 — armed nodes halted at H=$HALT_H"

    # LAYER SIGNATURE while halted: nothing may have been rejected at the
    # header-validation layer. A halted node has not judged anything invalid — it
    # has stopped. powrej > 0 here would mean a node is running rules it should not
    # have yet, i.e. the wrong binary.
    for n in node0 node1 node2; do
      pr="$(field "$(latest "$n")" powrej)"
      [[ "$pr" == "0" ]] \
        || die "$n reports powrej=$pr while HALTED — a halted node judges nothing invalid.
   That means it is running post-halt rules already. Wrong binary. STOP."
    done
    echo "   ✓ powrej=0 on every halted node — refusals are at the RELEASE layer only"
    # node3 never halts, so it must show no release-layer refusals at all.
    h3="$(field "$(latest node3)" hignore)"
    [[ "$h3" == "0" ]] \
      || die "node3 reports hignore=$h3 but it carries NO halt — wrong binary on node3. STOP."
    echo "   ✓ node3 hignore=0 — it is the un-armed old-binary miner, as intended"

    # H2 defines Halting as a real interval — reached H, boundary not yet final.
    # On the 6/5/5/5 net no node can finalize H alone, so the vote round MUST
    # happen; at a 5 s sampling cadence it should be caught. Report the finding
    # either way: a state the code defines and no run has ever shown is a claim,
    # not a behaviour.
    if dc logs --no-log-prefix node0 node1 node2 2>/dev/null | grep -q 'regime=Halting'; then
      echo "   ✓ regime=Halting OBSERVED during the boundary vote round:"
      dc logs --no-log-prefix node0 node1 node2 2>/dev/null | grep 'regime=Halting' | head -4 | sed 's/^/       /'
    else
      echo "   (finding) regime=Halting was NOT observed even at a 5 s sampling cadence."
      echo "             Record it as not-observed, with the vote-round duration, rather than"
      echo "             asserting the transition. Halting is covered in-process; this run"
      echo "             does not evidence it."
    fi
    halt_save_counters
    echo "   ✓ phase 1 complete: the armed nodes are HALTED at a finalized boundary."
    echo "   next: $0 halt-drill-b"
    ;;

  halt-drill-b)
    echo "== DRILL (b) — N2, the ⅔ gate =="
    echo "   Upgrading ONLY node0 (6 keys) + node1 (5 keys) = 11 keys < quorum 15."
    echo "   Finality MUST NOT resume: a minority committee does not limp forward."
    NODE0_BIN=qumbra-node-resume NODE1_BIN=qumbra-node-resume \
    NODE2_BIN=qumbra-node-armed  NODE3_BIN=qumbra-node \
      dc up -d node0 node1
    echo "   observing for 4 minutes (≈3 block times + a cadence)…"
    sleep 240
    "$0" halt-status
    halt_record "drill (b) — 11/21 keys upgraded"
    # N2's assertion is that finality does not advance ABOVE THE BOUNDARY. It is
    # deliberately NOT "final is unchanged": the finality TRACKER is not persisted
    # (M10-T0-5 / S7 — it rebuilds from re-gossip), so a just-restarted node
    # legitimately reports final=- for a while. That is a restart artefact, not lost
    # finality; the chain's finalized head is intact on disk. Reading it as a
    # regression would be the wrong alarm, so the check is numeric and one-sided.
    for n in node0 node1; do
      f="$(field "$(latest "$n")" final)"
      if [[ "$f" =~ ^[0-9]+$ ]] && (( f > HALT_H )); then
        die "$n FINALIZED $f > H=$HALT_H with only 11/21 keys upgraded — N2 VIOLATED.
   STOP EVERYTHING and preserve state."
      fi
      printf '     %-6s final=%-4s (- = tracker rebuilding after restart, expected)\n' "$n" "$f"
    done
    echo "   ✓ finality did not advance past H=$HALT_H with 11/21 keys upgraded — the ⅔ gate holds."
    echo "   next: $0 halt-drill-a"
    ;;

  halt-drill-a)
    echo "== DRILL (a) — H3, the hybrid honesty case =="
    echo "   Upgrading node2 as well → 16 keys ≥ quorum 15, so finality may resume."
    echo "   node3 stays on the OLD binary and keeps mining past H. Per"
    echo "   committee-and-governance §4 that is EXPECTED, not a defect: its blocks"
    echo "   can never finalize, and the fork resolves to the checkpointed branch."
    old_tip_before="$(field "$(latest node3)" tip)"
    NODE0_BIN=qumbra-node-resume NODE1_BIN=qumbra-node-resume \
    NODE2_BIN=qumbra-node-resume NODE3_BIN=qumbra-node \
      dc up -d node2
    echo "   waiting for the upgraded net to finalize past H=$HALT_H (up to 15 min)…"
    waited=0
    while (( waited < 900 )); do
      f="$(field "$(latest node0)" final)"
      [[ -n "$f" && "$f" != "-" ]] && (( f > HALT_H )) && break
      sleep 15; waited=$((waited + 15))
    done
    "$0" halt-status
    f0="$(field "$(latest node0)" final)"
    f3="$(field "$(latest node3)" final)"
    t3="$(field "$(latest node3)" tip)"
    [[ -n "$f0" && "$f0" != "-" ]] || die "node0 reports no finalized head — capture logs, STOP"
    (( f0 > HALT_H )) \
      || die "finality did NOT resume past H with 16/21 keys upgraded — investigate before continuing"
    echo "   ✓ the checkpointed branch finalized past H (node0 final=$f0)"
    # The old miner: its branch GROWS…
    if [[ -n "$t3" ]] && (( t3 > HALT_H )); then
      echo "   ✓ the old-binary miner grew past H (node3 tip=$t3, was $old_tip_before) — §4 expected"
    else
      echo "   (finding) node3 did not grow past H (tip=$t3) — the (a) case did not materialise;"
      echo "             record this honestly rather than reading it as a pass."
    fi
    # …and its finality STOPS ADVANCING while the checkpointed branch carries on.
    #
    # WHY NOT `node3.final > H`. That was this drill's original check and it is
    # UNSOUND — it fired on 2026-07-27 against a net that was behaving exactly as
    # §4 describes. A node's `final=` advances when it finalizes ANYONE's
    # checkpoint, including the one every other node finalized: node3 reported
    # `final=24` with `tip=23`, i.e. it had tracked the UPGRADED branch's
    # checkpoint, not produced one of its own. One checkpoint finalized, not two.
    #
    # The condition this check actually guards is "did a SECOND, DIFFERENT
    # checkpoint finalize at some height". Until 2026-07-29 that was NOT expressible
    # from telemetry, because TELEMETRY carried no checkpoint identity — and a
    # stop-check that cannot express the condition it guards will eventually fire on
    # the condition it can express instead, which is precisely what happened.
    #
    # Issue #84 (lab PR #110) closed that: `fid` is the finalized checkpoint's
    # identity, so `halt_assert_no_conflicting_finality` now compares identities at a
    # shared height and dies on the real condition instead of a proxy for it. It
    # says so explicitly when the running image is too old to carry the field, since
    # a silent pass is the same defect arriving from the other direction.
    #
    # The freeze check below is KEPT, and is no longer a proxy for the above — it
    # tests a different §4 expectation: the un-upgraded node's finality FREEZES while
    # the checkpointed branch keeps finalizing. It needs two samples spanning at
    # least one finalization on the checkpointed branch, driven by the condition
    # rather than by a fixed sleep, so it also surfaces a stalled checkpointed
    # branch as its own distinct finding.
    halt_assert_old_branch_finality_frozen
    halt_assert_no_conflicting_finality
    # Non-fatal, and node3 is included on purpose: it is the un-upgraded miner, so a
    # signed-variant split against it is expected here rather than alarming.
    halt_report_signed_divergence node0 node1 node2 node3
    halt_report_layers
    halt_record "drill (a) — after the swap"

    # LAYER SIGNATURE after the swap, at the precision the in-process drill asserts:
    #   pre-swap  (halted process):  hignore > 0, powrej = 0   → RELEASE layer
    #   post-swap (new process):     hignore = 0, powrej > 0   → HEADER-VALIDATION layer
    # The counters reset with the container, which is what makes the post-swap
    # hignore=0 meaningful rather than an artefact to explain away.
    echo "   -- layer transition (pre-swap values recorded at halt-arm) --"
    swap_evidence=0
    for n in node0 node1 node2; do
      pre_h="$(halt_preswap "$n" hignore)"; pre_p="$(halt_preswap "$n" powrej)"
      now_h="$(field "$(latest "$n")" hignore)"; now_p="$(field "$(latest "$n")" powrej)"
      printf '     %-6s pre: hignore=%-4s powrej=%-4s  →  post: hignore=%-4s powrej=%-4s\n' \
        "$n" "${pre_h:-?}" "${pre_p:-?}" "${now_h:-?}" "${now_p:-?}"
      [[ "$now_p" =~ ^[0-9]+$ ]] || continue
      if (( now_p > 0 )); then
        swap_evidence=1
        [[ "$now_h" == "0" ]] || echo "     (finding) $n powrej>0 AND hignore=$now_h — a resumed
     release carries no halt, so hignore must not climb after the swap. Investigate."
      fi
    done
    if (( swap_evidence == 1 )); then
      echo "   ✓ post-swap refusals are at the HEADER-VALIDATION layer (post-halt PoW domain)"
    else
      echo "   (finding) no upgraded node recorded powrej>0. Either node3's post-H blocks never"
      echo "             reached them, or the old branch was refused at some other layer."
      echo "             Record this honestly — the layer claim is NOT evidenced without it."
      echo "             Check: dc logs node0 | grep -E 'invalid header|above halt height'"
    fi
    echo "   next: $0 halt-drill-c"
    ;;

  halt-drill-c)
    echo "== DRILL (c) — H4, resume without a revision digest =="
    echo "   Starting node2 on qumbra-node-norev (resumes past H, carries NO revision)."
    echo "   It MUST refuse to start."
    dc stop node2 >/dev/null
    NODE0_BIN=qumbra-node-resume NODE1_BIN=qumbra-node-resume \
    NODE2_BIN=qumbra-node-norev  NODE3_BIN=qumbra-node \
      dc up -d node2 || true
    sleep 20
    out="$(dc logs --no-log-prefix --tail 40 node2 2>/dev/null || true)"
    echo "--- node2 output ---"; echo "$out"; echo "--------------------"
    if grep -q "carries NO revision" <<<"$out"; then
      echo "   ✓ the no-revision binary REFUSED to resume (H4)."
    else
      die "the no-revision binary did NOT refuse — H4 VIOLATED. STOP, preserve state."
    fi
    if docker inspect -f '{{.State.Running}}' "$(cid node2)" 2>/dev/null | grep -q true; then
      die "node2 is still RUNNING on the no-revision binary — H4 VIOLATED. STOP."
    fi
    echo "   restoring node2 to the proper upgrade binary…"
    NODE0_BIN=qumbra-node-resume NODE1_BIN=qumbra-node-resume \
    NODE2_BIN=qumbra-node-resume NODE3_BIN=qumbra-node \
      dc up -d node2
    echo "   next: $0 halt-drill-d   (destroys this net — capture evidence first)"
    ;;

  halt-drill-d)
    guard_rig
    echo "== DRILL (d) — N1, the stand-down =="
    echo "   Fresh net, ALL nodes on qumbra-node-cancel: the upgrade at H=$HALT_H was"
    echo "   stood down, so the net must mine and finalize straight through it."
    dc down -v >/dev/null 2>&1 || true
    docker network rm "$NET_SIDEB" 2>/dev/null || true
    NODE0_BIN=qumbra-node-cancel NODE1_BIN=qumbra-node-cancel \
    NODE2_BIN=qumbra-node-cancel NODE3_BIN=qumbra-node-cancel \
      dc up -d node0 node1 node2 node3
    want=$((HALT_H + 8))
    echo "   waiting for tip $want (past the cancelled height)…"
    wait_tip node0 "$want" 2400 || die "the cancelled net never reached $want — capture logs, STOP"
    sleep 60
    "$0" halt-status
    for n in "${NODES[@]}"; do
      line="$(latest "$n")"
      r="$(field "$line" regime)"; h="$(field "$line" halt)"; t="$(field "$line" tip)"
      [[ -n "$t" ]] || die "$n produced no telemetry — capture logs, STOP"
      [[ "$h" == "-" ]] || die "$n reports halt=$h — a CANCELLED upgrade must schedule no halt. STOP."
      if [[ "$r" == "Halting" || "$r" == "Halted" ]]; then
        die "$n reports regime=$r — a CANCELLED upgrade must never halt. STOP."
      fi
      (( t > HALT_H )) || die "$n tip=$t did not pass the cancelled height $HALT_H. STOP."
    done
    f="$(field "$(latest node0)" final)"
    [[ -n "$f" && "$f" != "-" ]] && (( f > HALT_H )) \
      || die "finality did not advance past the cancelled height (final=$f). STOP."
    echo "   ✓ the stand-down held: mined and finalized through H, never a halt regime."
    ;;

  halt-evidence)
    echo "== dumping halt-drill evidence to $EVID =="
    { echo "=== full telemetry history + refusal reasons, $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
      for n in "${NODES[@]}"; do
        echo "--- $n telemetry ---"
        dc logs --no-log-prefix "$n" 2>/dev/null | grep 'TELEMETRY tip=' || true
        echo "--- $n halt/refusal lines ---"
        dc logs --no-log-prefix "$n" 2>/dev/null \
          | grep -E 'halt-height|HALT|halt plan|revision:|refus|above halt height|invalid header' || true
      done
    } >> "$EVID"
    echo "   appended. Raw reasons are what the run doc's layer claim rests on."
    ;;

  teardown)
    dc down -v
    docker network rm "$NET_SIDEB" 2>/dev/null || true
    ;;

  *)
    # The whole leading comment block, not a fixed line range: `sed -n '2,60p'` was
    # already cutting the help off mid-drill before this file grew a netem section,
    # so the usage text silently stopped documenting the newest subcommands.
    awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
    exit 2
    ;;
esac
