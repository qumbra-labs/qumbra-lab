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
#                         <node_name> <public_addr host:port> <ssh_target | -> [miner_rkm]
#                       ssh_target "-" means LOCAL mode for that node (dry-run):
#                       the payload is copied into <local-base>/<node_name>.
#                       miner_rkm is per host: the 64-hex coinbase payee that
#                       node mines to (`qumbra-wallet miner-rkm`). REQUIRED on
#                       every host of a mining fleet, which is the default:
#                       `qumbra-node` REFUSES TO START with `mining = true` and
#                       no `miner_rkm` (lab #552, PR #655), so this tool refuses
#                       to GENERATE that — naming every keyless host, before it
#                       builds anything. Omit it (or write "-") ONLY under
#                       --no-mining. This column exists so the hosts file is
#                       the SOURCE OF TRUTH for the field: before it, a re-run
#                       silently dropped miner_rkm from every host that had it
#                       (OPERATOR §9.5.1).
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
#                       The ONLY fleet in which a host without a miner_rkm is
#                       generated; see --hosts.
#   --metrics-port N    Serve the /metrics scrape endpoint on 0.0.0.0:N (issue #87).
#                       OMITTED BY DEFAULT: no flag, no listener. Passing it also
#                       requires an inbound security-group rule SOURCE-RESTRICTED to
#                       the collector — see the note in the generated config.
#   --keep-stage        Keep the staging directory (default: removed on success).
#   -h | --help         This help.
#
# Exit non-zero on any failure (set -euo pipefail).

set -euo pipefail

# ---- constants (task-book inline stamps) ------------------------------------
readonly N_MACHINES=4
readonly N_KEYS=21
readonly KEY_SPLIT=(6 5 5 5)   # sums to 21; ~5-6 keys/node

# Mode for the committee-key directory, at BOTH ends of both transports. Not the
# umask default: see the block at the staging `install -d` below for why this is
# the one directory in the payload whose mode is load-bearing.
readonly KEYS_DIR_MODE=700

# ---- args -------------------------------------------------------------------
HOSTS_FILE=""
LOCAL_BASE="./t0-deploy"
REMOTE_ROOT="/opt/qumbra"
TARGET=""
BINARY=""
NO_BUILD=0
MINING="true"
METRICS_PORT=""
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
    --metrics-port) METRICS_PORT="${2:?}"; shift 2 ;;
    --keep-stage)  KEEP_STAGE=1; shift ;;
    -h|--help)     sed -n '2,55p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
NAMES=(); ADDRS=(); SSH=(); RKMS=()
while read -r name addr ssh rkm _rest; do
  [[ -z "${name:-}" || "${name:0:1}" == "#" ]] && continue
  # "-" is an explicit "this host has none", so a hosts file can keep its
  # columns aligned when only some nodes mine to a wallet.
  [[ "${rkm:-}" == "-" ]] && rkm=""
  # Shape only, and deliberately not a second copy of the node's rules: the
  # AUTHORITY is `qumbra-node check`, which parses this field with the node's
  # own parser (and refuses an all-zero one) — the dry-run runs that check on
  # every laid-down config. This catches the one error worth catching before a
  # 4-host rsync, a truncated paste, and says which host it is on.
  if [[ -n "${rkm:-}" && ! "$rkm" =~ ^[0-9a-fA-F]{64}$ ]]; then
    die "host '$name': miner_rkm must be 64 hex characters (got ${#rkm}). \
It is the value \`qumbra-wallet miner-rkm --dir DIR\` prints."
  fi
  NAMES+=("$name"); ADDRS+=("$addr"); SSH+=("$ssh"); RKMS+=("${rkm:-}")
done < "$HOSTS_FILE"

NODE_COUNT=${#NAMES[@]}
[[ "$NODE_COUNT" -eq "$N_MACHINES" ]] \
  || die "hosts file has $NODE_COUNT nodes; the T0 net is fixed at N_machines=$N_MACHINES"

# validate the key split
sum=0; for k in "${KEY_SPLIT[@]}"; do sum=$((sum + k)); done
[[ "$sum" -eq "$N_KEYS" ]] || die "KEY_SPLIT sums to $sum, not $N_KEYS"

# ---- the fleet's payout contract (lab #552, PR #655) -------------------------
#
# `qumbra-node` REFUSES TO START with `mining = true` and no `miner_rkm`: every
# coin such a node mined was paid to a fixed key nobody holds (T2 blocks 607/610/
# 611). Until lab #552 this tool generated exactly that for any host whose row
# had no key, and the binary then rejected it — one host at a time, on the host,
# after the rsync. Refuse HERE instead: before the build, before the genesis is
# minted, before any payload exists, naming every keyless host in one message
# (lab #475's thesis: catch it once, not one host at a time).
#
# Refuse rather than write `mining = false` for the keyless hosts. A generator
# that quietly decides which hosts mine is the same class of unexamined default
# that produced #552 — the flip would be at generation and the surprise at the
# first payout, and hosts.example's 1-keyed/3-keyless fleet would silently have
# become a one-miner net. The operator says which it is: a key on every row, or
# --no-mining for a rehearsal in which no host mines. Both are theirs to choose;
# neither is this script's.
#
# This IS a second copy of one of the node's rules, which the shape check above
# deliberately declines to be. The difference: that rule needs the node's parser
# and can drift from it; this one is "mining and no key", has nothing to drift,
# and is a property of the WHOLE fleet — which the per-host `check` cannot see,
# and which in remote mode nobody runs before the payload is on the host.
if [[ "$MINING" == "true" ]]; then
  keyless=()
  for i in "${!NAMES[@]}"; do
    [[ -z "${RKMS[$i]}" ]] && keyless+=("${NAMES[$i]}")
  done
  if [[ ${#keyless[@]} -gt 0 ]]; then
    die "mining fleet, but ${#keyless[@]} of $NODE_COUNT hosts carry no miner_rkm: ${keyless[*]}
  qumbra-node REFUSES TO START with mining = true and no miner_rkm (lab #552, PR #655):
  every coin such a host mined would be paid to a key nobody can spend. Nothing was
  built, minted or deployed. Choose one — in the hosts file, or on this command line:
    - give EVERY host a miner_rkm (\`qumbra-wallet miner-rkm --dir DIR\` prints it), or
    - pass --no-mining for a verify-only rehearsal in which no host mines.
  This tool will not flip a keyless host to mining = false on its own."
  fi
fi

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
# Printed as soon as the stage exists (not at the end), so it is available even if
# the run dies mid-way — and so a checker can assert the staged modes AT their
# creation site rather than at a downstream copy of them.
[[ "$KEEP_STAGE" -eq 1 ]] && echo "  stage:       $WORK  (kept: --keep-stage)"

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
  #
  # 0700 EXPLICITLY, not whatever the operator's umask gives. `genesis init` writes
  # keys/ at 0700 and each key at 0600 (issue #161), and both transports below
  # preserve modes — so the mode set HERE is the mode on four public-IP hosts.
  # The `cp` in the loop below carries the FILE mode faithfully, which is why a
  # check that only looks at file modes passes; the staging DIRECTORY got
  # 0755 from the default umask, and `rsync -a` then carried that 0755 to the live
  # net (found by hand after the 2026-07-31 genesis mint, `drwxr-xr-x /opt/qumbra/keys`).
  #
  # Fixed at creation rather than with `rsync --chmod`: --chmod fixes the transport
  # and leaves the stage wrong, so anyone who inspects the stage (--keep-stage) or
  # moves it another way gets 0755 back.
  key_paths=()
  stage="$WORK/stage/$name"
  install -d -m "$KEYS_DIR_MODE" "$stage/keys"
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

  # Per-host coinbase payee (OPERATOR §9.5.1, lab #475). Emitted from the hosts
  # file, never invented here. Absent ONLY for a keyless host under --no-mining:
  # the payout-contract refusal above guarantees a MINING fleet reaches this
  # point with a key on every host (lab #552). The point of the column is that
  # this is REGENERABLE: `deploy.sh` used to drop the field on every re-run, so
  # the live hosts' configs and the config the tool produced had permanently
  # diverged, and the fix was a hand edit after every deploy.
  if [[ -n "${RKMS[$i]}" ]]; then
    cat >> "$stage/node.toml" <<EOF
# Coinbase payee for this host (issue #101). 64 hex characters, lane-major LE —
# the value \`qumbra-wallet miner-rkm --dir DIR\` prints. Sourced from the
# --hosts file, so it survives regeneration; edit it THERE, not on the host.
miner_rkm = "${RKMS[$i]}"
EOF
  fi

  # /metrics scrape endpoint (issue #87). Absent unless --metrics-port was passed:
  # a node nobody scrapes listens on nothing extra, so this can never be left open
  # by forgetting to turn it off.
  if [[ -n "$METRICS_PORT" ]]; then
    # LOCAL mode stands four "hosts" up on ONE machine, so a single shared port
    # would collide and — since a failed bind is fatal by design — take three of
    # the four nodes down. Offset by node index there; on real hosts each node has
    # the port to itself, so it is used exactly as given (one SG rule, not four).
    if [[ "$ssh" == "-" ]]; then
      metrics_bind="127.0.0.1:$((METRICS_PORT + i))"
    else
      metrics_bind="0.0.0.0:$METRICS_PORT"
    fi
    cat >> "$stage/node.toml" <<EOF
# Prometheus scrape target (issue #87). Bound on all interfaces, so it is reachable
# ONLY as far as the host firewall allows: pair it with an inbound rule whose SOURCE
# is the collector's fixed address or security group — never 0.0.0.0/0, and never a
# roaming operator IP (a roaming source re-creates the 10.15 h blind spot of the 42 h
# soak, in a new place). Standalone aws_security_group_rule resources only: inline
# rules once silently deleted twelve peer P2P rules.
metrics_addr = "$metrics_bind"
EOF
  fi

  # rest of the payload
  cp "$BINARY" "$stage/qumbra-node"
  cp "$GEN_DIR/genesis.qmb" "$stage/genesis.qmb"

  # deploy the payload
  if [[ "$ssh" == "-" ]]; then
    echo "-- $name -> LOCAL $node_root ($n_keys keys, listen $listen)"
    mkdir -p "$node_root"
    # `$node_root` itself keeps the umask default: it holds genesis.qmb (public and
    # hash-pinned), node.toml (addresses and key PATHS, no key material), the binary
    # and data/. Only keys/ is tightened.
    #
    # keys/ is set here as well as on the stage because the two transports differ on
    # a RE-deploy: `rsync -a --delete` (remote) rewrites an existing directory's mode,
    # so a host laid down by the pre-fix script is repaired on the next deploy — but
    # `cp -R` (local) leaves an existing directory's mode alone, so a 0755 keys/ from
    # a pre-fix run would survive every future local deploy. Same trap `genesis.rs`
    # documents for `fs::write` not changing an existing file's mode.
    install -d -m "$KEYS_DIR_MODE" "$node_root/keys"
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
