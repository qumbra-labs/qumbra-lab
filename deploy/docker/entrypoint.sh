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
    rkm_line="$(qumbra-faucet address --config "$svc_cfg" | head -1)"
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
    echo "== faucet config =="
    cat "$svc_cfg"
    echo "== faucet node config =="
    cat "$node_cfg"
    # Pre-flight: the genesis byte-verify, the keyless check, and the payout check —
    # all of them before a socket is bound or a block is mined.
    qumbra-faucet check --config "$svc_cfg"
    exec qumbra-faucet run --config "$svc_cfg"
    ;;

  *)
    echo "entrypoint: unknown command '${cmd:-}' (expected: init | run <idx> | faucet)" >&2
    exit 2
    ;;
esac
