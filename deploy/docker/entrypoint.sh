#!/usr/bin/env bash
#
# Container entrypoint for the Qumbra T0 internal-net (Phase B-lite, docker mode).
#
#   entrypoint.sh init          mint the ONE shared genesis + 21 committee keys
#                               into /shared, exactly once (idempotent on restart)
#   entrypoint.sh run <idx>     generate node<idx>'s config from the fixed 4-node
#                               topology and run it (real TCP + RandomX + disk)
#   entrypoint.sh faucet        the T1 faucet listener on a KEYLESS node of its own
#                               (issue #123) — mints its own key material once into
#                               its data volume, mines to its own rkm, serves HTTP
#   entrypoint.sh pool          the T2 pool (lab #511 / G4) — talks to ITS OWN
#                               node on the same host via QUMBRA_NODE_RPC
#                               (default http://127.0.0.1:9420). That node must
#                               have template_serving = true.
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
# WHAT THIS HARNESS MODELS — three host properties, three independent knobs. The
# canonical list, with the caveat that belongs to each, is soak.sh's header; this file
# implements only the ones decided when a node's config is generated:
#
#   WAN latency                  `soak.sh netem <ms>` — a tc qdisc on the container's
#                                eth0. This script has no part in it at all.
#   advertised-address absence   QUMBRA_ADVERTISE_ADDR (below) — this script DECIDES
#                                it, by writing or omitting the key.
#   CPU budget                   docker-compose.yml's `cpus:`/`cpuset:` (or `soak.sh
#                                cpu-budget` live) DECIDES it; this script only
#                                REPORTS it, from the cgroup (see cpu_budget_line).
#
# The three are orthogonal — none of them reads either of the others — and each is
# stamped on its own greppable line, so every combination of the three is a legible
# run rather than something to be inferred afterwards.
#
# QUMBRA_ADVERTISE_ADDR selects whether this node declares itself dialable at all
# (issue #107 step 1c). It exists because the harness and the four T0 hosts differed
# here and the harness could not express the hosts' side:
#
#   auto   (default)  advertise_addr = "node<idx>:9401" — unchanged behaviour, what
#                     every run before 2026-07-30 did.
#   none              the key is OMITTED from the generated node.toml. This is the
#                     configuration the four T0 hosts actually run: their
#                     /opt/qumbra/node.toml predates the field (#86, 2026-07-28;
#                     hosts provisioned 2026-07-26) and an image roll does not
#                     regenerate it. Such a node dials out and is never gossiped.
#
# Anything else is a hard failure rather than a fallback: a typo here silently
# inverts the experiment, and the whole point of the toggle is to be sure which
# side of it a run was on.
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
#   docker compose logs faucet | grep CPU_BUDGET    # the fifth node reports too
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
# The T1 faucet's HTTP listener (issue #123). Same reasoning as TELEMETRY_PORT for
# the in-container bind; compose publishes it to 127.0.0.1 on the host.
FAUCET_PORT=9450
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
#
# The argument is the container's NAME, not a node index, because the faucet (#128) is
# a fifth container with a cgroup like any other and its run record needs the same
# line. `soak.sh cpu-show` greps `^CPU_BUDGET` and reads field 2 as the name.
cpu_budget_line() {   # cpu_budget_line <name>
  local who="$1" quota="unknown" cpuset="unknown" q p nproc_n
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
  echo "CPU_BUDGET $who quota=$quota cpuset=$cpuset nproc=$nproc_n"
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

    # Advertised address: present (default) or deliberately absent — see the header.
    # The `advertise_addr` line is assembled here rather than inside the heredoc so
    # that "absent" means the key is genuinely not in the file, not commented-out-but-
    # parsed or set to an empty string (both of which the node would read differently).
    adv_mode="${QUMBRA_ADVERTISE_ADDR:-auto}"
    case "$adv_mode" in
      auto)
        adv_line="advertise_addr = \"node$idx:$LISTEN_PORT\""
        adv_note="advertise_addr = \"node$idx:$LISTEN_PORT\""
        ;;
      none)
        adv_line="# advertise_addr: ABSENT ON PURPOSE (QUMBRA_ADVERTISE_ADDR=none, issue #107"
        adv_line+=$'\n'"#   step 1c) — models /opt/qumbra/node.toml on the four T0 hosts, which has"
        adv_line+=$'\n'"#   never carried this field. This node is never gossiped."
        adv_note="ABSENT from node.toml (never gossiped)"
        ;;
      *)
        echo "run: QUMBRA_ADVERTISE_ADDR must be 'auto' or 'none', got '$adv_mode'" >&2
        exit 2
        ;;
    esac

    mkdir -p "$DATA_DIR"
    cfg=/tmp/node.toml
    cat > "$cfg" <<EOF
# generated in-container by entrypoint.sh for node$idx (do not hand-edit)
data_dir = "$DATA_DIR"
listen_addr = "0.0.0.0:$LISTEN_PORT"
# Each container is reachable at its compose service name, so it declares
# itself dialable (issue #83). A node with no advertise_addr is never gossiped.
$adv_line
dial_peers = [$peers]
genesis_file = "$GENESIS_FILE"
committee_key_paths = [$keys]
mining = true
expected_genesis_hash = "$ghash"
telemetry_addr = "0.0.0.0:$TELEMETRY_PORT"
EOF
    # A run whose configuration is not in its own output cannot be trusted
    # afterwards, so stamp BOTH modelled host properties this script knows about on
    # their own greppable lines BEFORE the config dump — one per property, never
    # merged, because they are independent axes and a reader is usually asking about
    # exactly one of them:
    #
    #   docker compose logs node0 | grep ADVERTISE_MODE   # which side of step 1c
    #   docker compose logs node0 | grep CPU_BUDGET       # which side of step 1d
    #
    # (The third property, latency, is a qdisc applied from outside after the node is
    # up, so it cannot be stamped here — `soak.sh netem-show` is its readback.)
    echo "ADVERTISE_MODE node$idx=$adv_mode ($adv_note)"
    # Read from the cgroup, not from the environment: a run that does not record what
    # CPU it actually had cannot be compared with one that had more.
    cpu_budget_line "node$idx"
    echo "== node$idx config (binary: $BIN, advertise=$adv_mode) =="
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

  faucet)
    # The T1 faucet listener (issue #123), on a node of its own that holds NO
    # committee keys. `testnet-plan.md` §6.2: a node that holds committee keys
    # exposes nothing beyond P2P, so the faucet's hot spending key and the
    # committee's signing keys never share a host. `qumbra-faucet` REFUSES to start
    # if `committee_key_paths` is non-empty, so this is enforced, not documented.
    for _ in $(seq 1 120); do [[ -f "$HASH_FILE" && -f "$GENESIS_FILE" ]] && break; sleep 1; done
    [[ -f "$HASH_FILE" ]] || { echo "faucet: shared genesis never appeared" >&2; exit 1; }
    ghash="$(cat "$HASH_FILE")"

    mkdir -p "$DATA_DIR/node"
    svc_cfg="$DATA_DIR/faucet.toml"
    node_cfg="$DATA_DIR/faucet-node.toml"

    # (1) Key material, once, in the faucet's own persistent volume. `keygen` writes
    #     0600 and prints only the PUBLIC parts (the address and the rkm); it refuses
    #     to overwrite an existing file, so a restart reuses the same faucet identity
    #     and keeps whatever it has already mined.
    if [[ ! -f "$DATA_DIR/faucet.seed" ]]; then
      qumbra-faucet keygen --out "$DATA_DIR"
    else
      echo "faucet: reusing the existing seed in $DATA_DIR (restart-safe)"
    fi

    # (2) The service config. `0.0.0.0` INSIDE a container namespace on a private
    #     bridge is not a host-exposure decision — the same argument this file already
    #     makes for telemetry_addr. docker-compose publishes it to 127.0.0.1 on the
    #     HOST, so the loopback default survives the boundary that matters. On a real
    #     host, binding off-loopback is a deliberate deployment act paired with a
    #     source-restricted inbound rule, and `qumbra-faucet` says so loudly at
    #     startup every time it is not on loopback.
    #
    #     QUMBRA_FAUCET_TICKETS=open turns tickets OFF, which makes the faucet
    #     saturable by roughly a hundred subnets (qlab_faucet::policy is explicit
    #     about the price). Default is required.
    tickets=true
    [[ "${QUMBRA_FAUCET_TICKETS:-required}" == "open" ]] && tickets=false
    cat > "$svc_cfg" <<EOF
# generated in-container by entrypoint.sh (do not hand-edit)
listen_addr = "0.0.0.0:$FAUCET_PORT"
node_config = "$node_cfg"
seed_file = "$DATA_DIR/faucet.seed"
ticket_secret_file = "$DATA_DIR/faucet-tickets.secret"
tickets_required = $tickets
EOF

    # (3) The payout key, derived from the seed we just wrote. This is the whole
    #     funding story: the faucet's node mines to the faucet's own rkm, and
    #     `qumbra-faucet` refuses to start if the two do not match — because a faucet
    #     mining to somebody else's key looks perfectly healthy and is simply never
    #     funded, for as long as it runs.
    # `grep`, not `head -1`: `address` prints the rkm line AND the receive address,
    # and `head` closes the pipe after the first line, which makes the second
    # `println!` fail with EPIPE and panic (Rust does not ignore SIGPIPE). grep reads
    # to EOF, so the writer never sees a closed pipe. Observed on the first run.
    rkm_line="$(qumbra-faucet address --config "$svc_cfg" | grep '^miner_rkm')"
    echo "faucet: $rkm_line"

    # (4) The KEYLESS node config. Note `committee_key_paths` is absent (i.e. empty).
    peers=""
    for j in 0 1 2 3; do peers+="\"node$j:$LISTEN_PORT\", "; done
    peers="${peers%, }"
    cat > "$node_cfg" <<EOF
# generated in-container by entrypoint.sh for the faucet's KEYLESS node (#123)
data_dir = "$DATA_DIR/node"
listen_addr = "0.0.0.0:$LISTEN_PORT"
advertise_addr = "faucet:$LISTEN_PORT"
dial_peers = [$peers]
genesis_file = "$GENESIS_FILE"
committee_key_paths = []
mining = true
expected_genesis_hash = "$ghash"
telemetry_addr = "0.0.0.0:$TELEMETRY_PORT"
$rkm_line
EOF
    # The faucet MINES (see `mining = true` above), on the same synchronous main loop
    # the four nodes use, so it is a real competitor for the machine's cores and its
    # own budget belongs in its own record for exactly the reason theirs does. It is a
    # FIFTH container, not one of the four T0 hosts — `soak.sh cpu-show` reports it
    # apart from them for that reason.
    cpu_budget_line faucet
    echo "== faucet config =="
    cat "$svc_cfg"
    echo "== faucet node config =="
    cat "$node_cfg"
    # Pre-flight: the genesis byte-verify, the keyless check, and the payout check —
    # all of them before a socket is bound or a block is mined.
    qumbra-faucet check --config "$svc_cfg"
    exec qumbra-faucet run --config "$svc_cfg"
    ;;

  pool)
    # Lab #511: the pool talks to ITS OWN node on the same host. Default
    # node_rpc is the discovery loopback the node binds when discovery is
    # left at its default. Override QUMBRA_NODE_RPC if the node is bound
    # elsewhere. Config path is /tmp/pool.toml (generated) unless
    # QUMBRA_POOL_CONFIG points at an operator file.
    if [[ -n "${QUMBRA_POOL_CONFIG:-}" ]]; then
      echo "pool: using operator config $QUMBRA_POOL_CONFIG"
      exec qumbra-pool run --config "$QUMBRA_POOL_CONFIG"
    fi
    listen="${QUMBRA_POOL_LISTEN:-0.0.0.0:3333}"
    share="${QUMBRA_POOL_SHARE_DIFFICULTY:-1024}"
    node_rpc="${QUMBRA_NODE_RPC:-http://127.0.0.1:9420}"
    poll="${QUMBRA_POOL_POLL_MS:-1000}"
    cfg=/tmp/pool.toml
    cat > "$cfg" <<EOF
# generated in-container by entrypoint.sh pool (lab #511)
listen_addr = "$listen"
share_difficulty = $share
node_rpc = "$node_rpc"
poll_ms = $poll
EOF
    cpu_budget_line pool
    echo "== pool config =="
    cat "$cfg"
    qumbra-pool check --config "$cfg"
    exec qumbra-pool run --config "$cfg"
    ;;

  *)
    echo "entrypoint: unknown command '${cmd:-}' (expected: init | run <idx> | faucet | pool)" >&2
    exit 2
    ;;
esac
