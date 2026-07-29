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
    # afterwards, so stamp the advertise mode on one greppable line of its own
    # BEFORE the config dump — `docker compose logs node$idx | grep ADVERTISE_MODE`
    # answers "which side of the experiment was this node on" with no inference.
    echo "ADVERTISE_MODE node$idx=$adv_mode ($adv_note)"
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

  *)
    echo "entrypoint: unknown command '${cmd:-}' (expected: init | run <idx>)" >&2
    exit 2
    ;;
esac
