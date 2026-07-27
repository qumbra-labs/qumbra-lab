#!/usr/bin/env bash
#
# Qumbra T0 internal-net deploy tool (M10-T0-3 item 1).
#
# rsync/ssh grade, no k8s. Builds the `qumbra-node` binary once, generates ONE
# shared genesis file + the 21 committee signing keys, then for each node:
#   - generates a per-node config (its listen addr, the mesh dial-peer list, the
#     pinned genesis hash, and ONLY the committee keys that node holds),
#   - stages a payload (binary + genesis + that node's keys + config),
#   - deploys it — either to a real host over rsync/ssh, or (dry-run) into a local
#     directory standing in for the host.
#
# N_machines = 4 (inline stamp per the task-book; allows a 2+2 partition). The 21
# committee keys split 6/5/5/5 across the 4 nodes (a 2+2 partition leaves at most
# 11 keys either side, below the 15-quorum — finality correctly STALLS under
# partition, which is what soak scenarios (c)/(d) exercise).
#
# Usage:
#   deploy.sh --hosts FILE [options]
#
#   --hosts FILE        Required. Node spec, one node per line (see hosts.example):
#                         <node_name> <public_addr host:port> <ssh_target | ->
#                       ssh_target "-" means LOCAL mode for that node (dry-run):
#                       the payload is copied into <local-base>/<node_name>.
#   --local-base DIR    Root for LOCAL-mode nodes (default: ./t0-deploy). Each
#                       local node lands in DIR/<node_name>/ (an absolute path is
#                       baked into that node's config).
#   --remote-root PATH  Install root on REAL hosts (default: /opt/qumbra).
#   --target TRIPLE     cargo --target for the build (e.g. x86_64-unknown-linux-gnu
#                       for Linux VPSes). Default: host-native. See README for the
#                       RandomX cross-compile caveat.
#   --binary PATH       Use a pre-built binary instead of building.
#   --no-build          Do not build; expect the binary at the default path.
#   --no-mining         Generate configs with mining = false (verify-only rehearsal).
#   --keep-stage        Keep the staging directory (default: removed on success).
#   -h | --help         This help.
#
# Exit non-zero on any failure (set -euo pipefail).

set -euo pipefail

# ---- constants (task-book inline stamps) ------------------------------------
readonly N_MACHINES=4
readonly N_KEYS=21
readonly KEY_SPLIT=(6 5 5 5)   # sums to 21; ~5-6 keys/node

# ---- args -------------------------------------------------------------------
HOSTS_FILE=""
LOCAL_BASE="./t0-deploy"
REMOTE_ROOT="/opt/qumbra"
TARGET=""
BINARY=""
NO_BUILD=0
MINING="true"
KEEP_STAGE=0

die() { echo "deploy: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts)       HOSTS_FILE="${2:?}"; shift 2 ;;
    --local-base)  LOCAL_BASE="${2:?}"; shift 2 ;;
    --remote-root) REMOTE_ROOT="${2:?}"; shift 2 ;;
    --target)      TARGET="${2:?}"; shift 2 ;;
    --binary)      BINARY="${2:?}"; shift 2 ;;
    --no-build)    NO_BUILD=1; shift ;;
    --no-mining)   MINING="false"; shift ;;
    --keep-stage)  KEEP_STAGE=1; shift ;;
    -h|--help)     sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)             die "unknown option: $1 (see --help)" ;;
  esac
done

[[ -n "$HOSTS_FILE" ]] || die "--hosts FILE is required (see --help)"
[[ -f "$HOSTS_FILE" ]] || die "hosts file not found: $HOSTS_FILE"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# absolute path of a (possibly not-yet-existing) directory
abspath() { mkdir -p "$1"; (cd "$1" && pwd); }

# ---- parse the hosts spec ---------------------------------------------------
NAMES=(); ADDRS=(); SSH=()
while read -r name addr ssh _rest; do
  [[ -z "${name:-}" || "${name:0:1}" == "#" ]] && continue
  NAMES+=("$name"); ADDRS+=("$addr"); SSH+=("$ssh")
done < "$HOSTS_FILE"

NODE_COUNT=${#NAMES[@]}
[[ "$NODE_COUNT" -eq "$N_MACHINES" ]] \
  || die "hosts file has $NODE_COUNT nodes; the T0 net is fixed at N_machines=$N_MACHINES"

# validate the key split
sum=0; for k in "${KEY_SPLIT[@]}"; do sum=$((sum + k)); done
[[ "$sum" -eq "$N_KEYS" ]] || die "KEY_SPLIT sums to $sum, not $N_KEYS"

echo "== Qumbra T0 deploy =="
echo "  nodes:       $NODE_COUNT  (${NAMES[*]})"
echo "  key split:   ${KEY_SPLIT[*]}  (= $N_KEYS keys)"
echo "  remote root: $REMOTE_ROOT"
echo "  local base:  $LOCAL_BASE"

# ---- locate / build the binary ----------------------------------------------
if [[ -z "$BINARY" ]]; then
  if [[ -n "$TARGET" ]]; then
    BINARY="$REPO_ROOT/target/$TARGET/release/qumbra-node"
  else
    BINARY="$REPO_ROOT/target/release/qumbra-node"
  fi
  if [[ "$NO_BUILD" -eq 0 ]]; then
    echo "== building qumbra-node (release${TARGET:+, target=$TARGET}) =="
    ( cd "$REPO_ROOT" && cargo build --release -p qumbra-node ${TARGET:+--target "$TARGET"} )
  fi
fi
[[ -x "$BINARY" ]] || die "binary not found/executable: $BINARY"
echo "  binary:      $BINARY"

# ---- staging workspace ------------------------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/qmb-t0-deploy.XXXXXX")"
cleanup() { [[ "$KEEP_STAGE" -eq 1 ]] || rm -rf "$WORK"; }
trap cleanup EXIT

# ---- generate the ONE shared genesis + 21 keys ------------------------------
echo "== generating genesis + $N_KEYS committee keys =="
GEN_DIR="$WORK/genesis"
"$BINARY" genesis init --out "$GEN_DIR" > "$WORK/genesis-init.log"
GENESIS_HASH="$(grep 'GENESIS HASH' "$WORK/genesis-init.log" | awk '{print $NF}')"
[[ -n "$GENESIS_HASH" ]] || die "could not read the genesis hash from genesis init"
[[ -f "$GEN_DIR/genesis.qmb" ]] || die "genesis init produced no genesis.qmb"
echo "  genesis hash: $GENESIS_HASH"

# ---- per-node staging + deploy ----------------------------------------------
key_start=0
for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"; addr="${ADDRS[$i]}"; ssh="${SSH[$i]}"
  n_keys="${KEY_SPLIT[$i]}"
  port="${addr##*:}"

  # this node's install root (destination): the local dir, or the remote root.
  if [[ "$ssh" == "-" ]]; then
    node_root="$(abspath "$LOCAL_BASE/$name")"
    listen="$addr"                 # loopback in dry-run
  else
    node_root="$REMOTE_ROOT"
    listen="0.0.0.0:$port"
  fi

  # dial peers = every OTHER node's public address (full mesh)
  peers=()
  for j in "${!NAMES[@]}"; do
    [[ "$j" -ne "$i" ]] && peers+=("\"${ADDRS[$j]}\"")
  done
  peers_csv="$(IFS=, ; echo "${peers[*]}")"

  # this node's committee key files (its slice of the 21)
  key_paths=()
  stage="$WORK/stage/$name"
  mkdir -p "$stage/keys"
  for ((k=0; k<n_keys; k++)); do
    idx=$((key_start + k))
    kf="$(printf 'committee-%02d.key' "$idx")"
    cp "$GEN_DIR/keys/$kf" "$stage/keys/$kf"
    key_paths+=("\"$node_root/keys/$kf\"")
  done
  keys_csv="$(IFS=, ; echo "${key_paths[*]}")"
  key_start=$((key_start + n_keys))

  # per-node config (absolute destination paths baked in)
  cat > "$stage/node.toml" <<EOF
# qumbra-node config — $name (M10-T0-3 T0 internal net)
# generated by deploy/deploy.sh; do not hand-edit on the host.
data_dir = "$node_root/data"
listen_addr = "$listen"
# This node's own publicly dialable address. The T0 hosts ARE the stable seed
# set (issue #83, condition 1 of the NAT decision), so each declares itself
# reachable — that declaration is the only way peers are told about it.
advertise_addr = "${ADDRS[$i]}"
# SEED peers. Discovery fills the rest of the book from Addr gossip; these are
# the entries that are never evicted.
dial_peers = [$peers_csv]
genesis_file = "$node_root/genesis.qmb"
committee_key_paths = [$keys_csv]
mining = $MINING
expected_genesis_hash = "$GENESIS_HASH"
EOF

  # rest of the payload
  cp "$BINARY" "$stage/qumbra-node"
  cp "$GEN_DIR/genesis.qmb" "$stage/genesis.qmb"

  # deploy the payload
  if [[ "$ssh" == "-" ]]; then
    echo "-- $name -> LOCAL $node_root ($n_keys keys, listen $listen)"
    mkdir -p "$node_root"
    cp -R "$stage/." "$node_root/"
  else
    echo "-- $name -> $ssh:$node_root ($n_keys keys, listen $listen)"
    ssh "$ssh" "mkdir -p '$node_root'"
    # --delete, NOT --delete-excluded. macOS now ships openrsync (protocol 29) as
    # `rsync`, while a Debian host runs GNU rsync 3.2.7 (protocol 32); with
    # --delete-excluded openrsync emits an exclude-rules stream that GNU 3.2.7
    # mis-parses and dies on ("buffer overflow: recv_rules", exclude.c:1683), leaving
    # the payload undelivered. This script declares no --exclude rules, so
    # --delete-excluded only ever meant --delete here — the semantics are unchanged
    # and the mac-to-Linux path now works.
    rsync -a --delete "$stage/" "$ssh:$node_root/"
  fi
done

echo "== deploy complete =="
echo "genesis hash (pin on every node): $GENESIS_HASH"
echo "start each node with:  (cd <node_root> && ./qumbra-node run --config node.toml)"
echo "pre-flight a node:     <node_root>/qumbra-node check --config <node_root>/node.toml"
