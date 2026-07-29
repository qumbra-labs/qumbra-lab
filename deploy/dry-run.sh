#!/usr/bin/env bash
#
# Phase-A dry-run of the whole T0 deploy against 4 LOCAL directories standing in
# for the 4 VPS hosts (M10-T0-3 item 1, no VPS needed).
#
# Runs deploy.sh in local mode against a generated 4-node hosts spec, then asserts
# the laid-down layout is correct and STARTABLE through the real code paths:
#   1. every node dir has the binary + genesis + config + its key subset,
#   2. the 21 keys split 6/5/5/5, disjoint and complete (union == 0..20),
#   3. the genesis file is byte-identical on all 4 nodes,
#   4. `qumbra-node check` passes on every node (real verify_startup + key
#      cross-check against committee₀), reporting the same pinned genesis hash.
#
# Exit non-zero on the first failed assertion.
#
# Usage: dry-run.sh [--base DIR] [--keep]
#   --base DIR   Where to lay down the 4 node dirs (default: a fresh mktemp dir).
#   --keep       Keep the dry-run tree on success (default: removed).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BASE=""
KEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) BASE="${2:?}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "dry-run: unknown option $1" >&2; exit 2 ;;
  esac
done

[[ -n "$BASE" ]] || BASE="$(mktemp -d "${TMPDIR:-/tmp}/qmb-t0-dryrun.XXXXXX")"
BASE="$(cd "$BASE" && pwd)"
cleanup() { [[ "$KEEP" -eq 1 ]] || rm -rf "$BASE"; }
trap cleanup EXIT

pass() { echo "  ok  - $*"; }
fail() { echo "  FAIL- $*" >&2; exit 1; }

echo "== T0 deploy dry-run =="
echo "  base: $BASE"

# ensure a binary exists (build once if needed)
BINARY="$REPO_ROOT/target/release/qumbra-node"
if [[ ! -x "$BINARY" ]]; then
  echo "== building qumbra-node (release) =="
  ( cd "$REPO_ROOT" && cargo build --release -p qumbra-node )
fi

# a 4-node LOCAL hosts spec (ssh target "-" = local dir)
HOSTS="$BASE/hosts.local"
cat > "$HOSTS" <<'EOF'
# name  public_addr        ssh_target(-=local)
node0   127.0.0.1:9401     -
node1   127.0.0.1:9402     -
node2   127.0.0.1:9403     -
node3   127.0.0.1:9404     -
EOF

echo "== running deploy.sh (local mode) =="
# --metrics-port exercises issue #87's scrape opt-in through the REAL config path:
# NodeConfig uses deny_unknown_fields, so a config carrying metrics_addr that the
# binary did not understand would fail `check` rather than be ignored.
"$SCRIPT_DIR/deploy.sh" \
  --hosts "$HOSTS" \
  --local-base "$BASE/nodes" \
  --metrics-port 9090 \
  --binary "$BINARY"

echo "== assertions =="
NODES=(node0 node1 node2 node3)
EXPECT_KEYS=(6 5 5 5)
declare -a HASHES=()
ALL_KEY_IDX=""

for i in "${!NODES[@]}"; do
  name="${NODES[$i]}"
  root="$BASE/nodes/$name"

  # 1. payload present
  for f in qumbra-node genesis.qmb node.toml; do
    [[ -e "$root/$f" ]] || fail "$name: missing $f"
  done
  pass "$name: binary + genesis + config present"

  # 2. key subset count + collect indices
  got_keys=$(find "$root/keys" -name 'committee-*.key' | wc -l | tr -d ' ')
  [[ "$got_keys" -eq "${EXPECT_KEYS[$i]}" ]] \
    || fail "$name: expected ${EXPECT_KEYS[$i]} keys, found $got_keys"
  for kf in "$root"/keys/committee-*.key; do
    idx="$(basename "$kf" .key)"; idx="${idx#committee-}"
    ALL_KEY_IDX+="$idx "
  done
  pass "$name: holds $got_keys committee keys"

  # 3. genesis byte-identical vs node0
  if [[ "$i" -gt 0 ]]; then
    cmp -s "$BASE/nodes/node0/genesis.qmb" "$root/genesis.qmb" \
      || fail "$name: genesis.qmb differs from node0"
  fi

  # 4. issue #87: the scrape opt-in reached the config, bound to all interfaces
  #    (the operator's SG rule is what restricts it), and is annotated.
  # Local mode offsets the port per node so four stand-in "hosts" on one machine
  # do not collide on a bind that is fatal by design.
  grep -q "^metrics_addr = \"127.0.0.1:$((9090 + i))\"\$" "$root/node.toml" \
    || fail "$name: --metrics-port did not reach node.toml with the local offset"
  grep -q 'SOURCE-RESTRICTED\|SOURCE' "$root/node.toml" \
    || fail "$name: metrics_addr is not annotated with its security-group requirement"
  pass "$name: /metrics opt-in present and annotated"

  # 5. real preflight via the deployed binary (bind nothing)
  out="$("$root/qumbra-node" check --config "$root/node.toml")"
  echo "$out" | grep -q 'check: OK' || fail "$name: preflight did not pass"
  h="$(echo "$out" | awk '/genesis hash:/{print $NF}')"
  kh="$(echo "$out" | awk '/keys held:/{print $NF}')"
  [[ "$kh" -eq "${EXPECT_KEYS[$i]}" ]] || fail "$name: preflight keys-held $kh != ${EXPECT_KEYS[$i]}"
  HASHES+=("$h")
  pass "$name: qumbra-node check OK (keys held $kh, genesis $h)"
done

# 2b. keys disjoint + complete: sorted unique indices == 00..20
uniq_idx="$(echo "$ALL_KEY_IDX" | tr ' ' '\n' | grep -v '^$' | sort -u)"
uniq_count="$(echo "$uniq_idx" | wc -l | tr -d ' ')"
want_idx="$(seq -w 0 20)"
[[ "$uniq_count" -eq 21 ]] || fail "key union has $uniq_count distinct indices, want 21 (overlap/gap)"
[[ "$uniq_idx" == "$want_idx" ]] || fail "key union != 00..20 (disjoint+complete check failed)"
pass "21 keys split disjoint + complete across the 4 nodes"

# 5. all nodes pinned to the same genesis hash
base_hash="${HASHES[0]}"
for h in "${HASHES[@]}"; do
  [[ "$h" == "$base_hash" ]] || fail "genesis hash mismatch across nodes ($h != $base_hash)"
done
pass "all 4 nodes pinned to genesis $base_hash"

echo "== DRY-RUN PASSED =="
echo "genesis hash: $base_hash"
[[ "$KEEP" -eq 1 ]] && echo "tree kept at: $BASE"
exit 0
