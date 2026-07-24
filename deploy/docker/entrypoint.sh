#!/usr/bin/env bash
#
# Container entrypoint for the Qumbra T0 internal-net (Phase B-lite, docker mode).
#
#   entrypoint.sh init          mint the ONE shared genesis + 21 committee keys
#                               into /shared, exactly once (idempotent on restart)
#   entrypoint.sh run <idx>     generate node<idx>'s config from the fixed 4-node
#                               topology and run it (real TCP + RandomX + disk)
#
# The topology mirrors deploy/deploy.sh's inline stamps: N=4, keys split 6/5/5/5,
# full mesh (each node dials the other three by compose service name). The genesis
# is generated once by the `init` service into a shared volume; every node byte-
# verifies it and pins its hash (expected_genesis_hash) on startup.

set -euo pipefail

GENESIS_DIR=/shared
DATA_DIR=/data
LISTEN_PORT=9401
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
dial_peers = [$peers]
genesis_file = "$GENESIS_FILE"
committee_key_paths = [$keys]
mining = true
expected_genesis_hash = "$ghash"
EOF
    echo "== node$idx config =="
    cat "$cfg"
    # Pre-flight (byte-verify genesis + cross-check keys), then run.
    qumbra-node check --config "$cfg"
    exec qumbra-node run --config "$cfg"
    ;;

  *)
    echo "entrypoint: unknown command '${cmd:-}' (expected: init | run <idx>)" >&2
    exit 2
    ;;
esac
