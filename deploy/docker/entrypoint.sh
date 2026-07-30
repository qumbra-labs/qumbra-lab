#!/usr/bin/env bash
#
# Container entrypoint for the Qumbra T0 internal-net (Phase B-lite, docker mode).
#
#   entrypoint.sh init          mint the ONE shared genesis + 21 committee keys
#                               into /shared, exactly once (idempotent on restart)
#   entrypoint.sh run <idx>     generate node<idx>'s config from the fixed 4-node
#                               topology and run it (real TCP + RandomX + disk)
#
# QUMBRA_BIN selects WHICH node binary runs (issue #74). The halt height is a
# compile-time release constant with no runtime override (H1), so a "binary swap"
# in the drill is literally a different executable in this image:
#   qumbra-node          the un-armed v1.0 release (default)
#   qumbra-node-armed    halts at DRILL_HALT_HEIGHT (16)
#   qumbra-node-resume   the upgrade: inert revision v1.0.1-drill, resumes past 16
#   qumbra-node-norev    drill (c): resumes with NO revision — must refuse to start
#   qumbra-node-cancel   drill (d): the stand-down — does not halt at 16
# The genesis is ALWAYS minted by the plain binary: the genesis file is identical
# across releases, and the drill would be worthless if it were not.
#
# The topology mirrors deploy/deploy.sh's inline stamps: N=4, keys split 6/5/5/5,
# full mesh (each node dials the other three by compose service name). The genesis
# is generated once by the `init` service into a shared volume; every node byte-
# verifies it and pins its hash (expected_genesis_hash) on startup.
#
# CPU BUDGET (issue #107 step 1d). This script does not SET the budget — docker-
# compose.yml does, via `cpus:` / `cpuset:` — but it REPORTS it, on one greppable
# `CPU_BUDGET` line before the config dump, and it reports it by reading this
# container's own cgroup rather than the environment that was passed in. That
# distinction is the whole point: the environment says what was *requested*, the
# cgroup says what the kernel will actually enforce, and only the second one belongs
# in a run's record. A run whose resource envelope is not in its own output cannot be
# trusted afterwards, which is the same rule the config dump itself follows.
#
#   docker compose logs node0 | grep CPU_BUDGET     # what this node actually got
#
# The line carries three separate facts because they can disagree and the difference
# matters: the CFS quota (CPU-seconds per second), the effective cpuset (which cores
# the container may run on) and `nproc` (how many the process can SEE). `cpus: 2`
# alone leaves `nproc` at the host's count; only a 2-core `cpuset` makes a container
# look like the 2 vCPU t4g.small the T0 hosts are.

set -euo pipefail

GENESIS_DIR=/shared
DATA_DIR=/data
LISTEN_PORT=9401
# The /v1/telemetry read endpoint (issue #117) — the wire `qumbra-opview` polls.
# In-container it is the same port on every node; docker-compose publishes each to
# a distinct HOST port (9410..9413) so the view can be run from the host.
# `0.0.0.0` here is inside a container namespace on a private bridge, not a host
# exposure decision; on a real host the same key is paired with a
# source-restricted inbound rule (see config.rs's doc for `telemetry_addr`).
TELEMETRY_PORT=9410
GENESIS_FILE="$GENESIS_DIR/genesis.qmb"
INIT_LOG="$GENESIS_DIR/genesis-init.log"
HASH_FILE="$GENESIS_DIR/genesis.hash"

# Key split 6/5/5/5 across node0..node3 (task-book inline stamp; a 2+2 partition
# leaves 11 keys | 10 keys, both below the 15 quorum → finality correctly stalls).
KEY_SPLIT=(6 5 5 5)

# ── the effective CPU budget, read from the cgroup (issue #107 step 1d) ───────
#
# cgroup v2 is what Docker Desktop and Debian 12 both use; the v1 branch is here
# because a wrong-but-confident "unconstrained" on an older host would be worse than
# no line at all. Anything unreadable prints `unknown`, never a guess — this line is
# evidence, so it is allowed to say it does not know.
#
# The arithmetic is bash-only on purpose: the runtime image is debian:bookworm-slim
# plus four packages, and reaching for `awk`/`bc` here would make the run's own
# evidence line depend on a package nobody declared.
cpu_budget_line() {
  local idx="$1" quota="unknown" cpuset="unknown" q p nproc_n
  if [[ -r /sys/fs/cgroup/cpu.max ]]; then                       # cgroup v2
    read -r q p < /sys/fs/cgroup/cpu.max || true
  elif [[ -r /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]]; then        # cgroup v1
    q="$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)"               # -1 = no quota
    p="$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)"
    [[ "$q" == "-1" ]] && q=max
  fi
  if [[ "${q:-}" == "max" ]]; then
    quota="unconstrained"
  elif [[ "${q:-}" =~ ^[0-9]+$ && "${p:-0}" =~ ^[1-9][0-9]*$ ]]; then
    # Two decimals without a float: hundredths of a CPU, then split.
    local h=$(( q * 100 / p ))
    quota="$(( h / 100 )).$(printf '%02d' $(( h % 100 )))cpu"
  fi
  for f in /sys/fs/cgroup/cpuset.cpus.effective /sys/fs/cgroup/cpuset/cpuset.cpus; do
    [[ -r "$f" ]] && { cpuset="$(cat "$f")"; break; }
  done
  # `nproc` is what the PROCESS sees (sched_getaffinity), so it tracks the cpuset and
  # is blind to the quota. Printing both is how a reader tells the two apart.
  nproc_n="$(nproc 2>/dev/null || echo unknown)"
  echo "CPU_BUDGET node$idx quota=$quota cpuset=$cpuset nproc=$nproc_n"
}

cmd="${1:-}"
shift || true

case "$cmd" in
  init)
    mkdir -p "$GENESIS_DIR"
    if [[ -f "$GENESIS_FILE" ]]; then
      echo "init: genesis already present at $GENESIS_FILE — reusing (bake-once)"
      [[ -f "$INIT_LOG" ]] || qumbra-node genesis init --out "$GENESIS_DIR" | tee "$INIT_LOG"
    else
      qumbra-node genesis init --out "$GENESIS_DIR" | tee "$INIT_LOG"
    fi
    grep 'GENESIS HASH' "$INIT_LOG" | awk '{print $NF}' > "$HASH_FILE"
    echo "init: genesis hash $(cat "$HASH_FILE")"
    ;;

  run)
    idx="${1:?run needs a node index 0..3}"
    BIN="${QUMBRA_BIN:-qumbra-node}"
    command -v "$BIN" >/dev/null || { echo "run: unknown binary '$BIN'" >&2; exit 2; }
    # The init service completes first (compose depends_on), but be robust to races.
    for _ in $(seq 1 120); do [[ -f "$HASH_FILE" && -f "$GENESIS_FILE" ]] && break; sleep 1; done
    [[ -f "$HASH_FILE" ]] || { echo "run: shared genesis never appeared" >&2; exit 1; }
    ghash="$(cat "$HASH_FILE")"

    # This node's slice of the 21 committee keys.
    start=0
    for ((i = 0; i < idx; i++)); do start=$((start + KEY_SPLIT[i])); done
    n="${KEY_SPLIT[idx]}"
    keys=""
    for ((k = 0; k < n; k++)); do
      kf="$(printf 'committee-%02d.key' $((start + k)))"
      keys+="\"$GENESIS_DIR/keys/$kf\", "
    done
    keys="${keys%, }"

    # Full mesh: dial the other three by compose service name.
    peers=""
    for j in 0 1 2 3; do
      [[ "$j" -ne "$idx" ]] && peers+="\"node$j:$LISTEN_PORT\", "
    done
    peers="${peers%, }"

    mkdir -p "$DATA_DIR"
    cfg=/tmp/node.toml
    cat > "$cfg" <<EOF
# generated in-container by entrypoint.sh for node$idx (do not hand-edit)
data_dir = "$DATA_DIR"
listen_addr = "0.0.0.0:$LISTEN_PORT"
# Each container is reachable at its compose service name, so it declares
# itself dialable (issue #83). A node with no advertise_addr is never gossiped.
advertise_addr = "node$idx:$LISTEN_PORT"
dial_peers = [$peers]
genesis_file = "$GENESIS_FILE"
committee_key_paths = [$keys]
mining = true
expected_genesis_hash = "$ghash"
telemetry_addr = "0.0.0.0:$TELEMETRY_PORT"
EOF
    # The resource envelope BEFORE the config dump, on its own greppable line — a run
    # that does not record what CPU it had cannot be compared with one that had more
    # (issue #107 step 1d). Read from the cgroup, not from the environment.
    cpu_budget_line "$idx"
    echo "== node$idx config (binary: $BIN) =="
    cat "$cfg"
    # The halt-height release status of THIS binary, before anything else (#74).
    # `halt-status` exits non-zero if this release refuses to start — which is
    # exactly what drill (c) is supposed to demonstrate, so let it fail loudly here.
    "$BIN" halt-status --config "$cfg"
    # Pre-flight (byte-verify genesis + cross-check keys + halt gates), then run.
    "$BIN" check --config "$cfg"
    # QUMBRA_SAMPLE_SECS is OBSERVABILITY ONLY (telemetry print cadence). The halt
    # drill sets it low so the short `regime=Halting` interval — tip at H, waiting
    # for H's checkpoint to close — is actually sampled rather than falling between
    # two 30 s prints. It touches nothing consensus-side.
    exec "$BIN" run --config "$cfg" --sample-interval-secs "${QUMBRA_SAMPLE_SECS:-30}"
    ;;

  *)
    echo "entrypoint: unknown command '${cmd:-}' (expected: init | run <idx>)" >&2
    exit 2
    ;;
esac
