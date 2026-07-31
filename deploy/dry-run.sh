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
#      cross-check against committee₀), reporting the same pinned genesis hash,
#   5. the committee keys are laid down at 0700 on the DIRECTORY and 0600 on each
#      FILE — asserted in the deployed tree, in the staging tree they were copied
#      from, and again after a re-deploy over a deliberately loosened tree.
#
# Why (5) is three assertions and not one: the defect it guards against left every
# key FILE correctly 0600 and only the enclosing DIRECTORY world-searchable, so a
# file-mode check passed while four public-IP hosts ran `drwxr-xr-x /opt/qumbra/keys`.
# Asserting the deployed copy alone would also pass for a fix applied to the copy
# instead of the stage, and a fresh-tree assertion cannot see that `cp -R` leaves an
# existing directory's mode alone where `rsync -a` rewrites it.
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
# Set by pass 2 (deploy.sh --keep-stage); removed with the rest on exit.
STAGE=""
cleanup() {
  [[ "$KEEP" -eq 1 ]] || rm -rf "$BASE"
  [[ -z "$STAGE" || "$KEEP" -eq 1 ]] || rm -rf "$STAGE"
  return 0
}
trap cleanup EXIT

pass() { echo "  ok  - $*"; }
fail() { echo "  FAIL- $*" >&2; exit 1; }

# A path's permission bits as octal, without a leading 0. BSD stat (macOS, where
# the staging half of a deploy runs) and GNU stat (Linux) spell this differently.
mode_of() { stat -f '%OLp' "$1" 2>/dev/null || stat -c '%a' "$1"; }

# Assert keys/ is 0700 and every committee key in it is 0600, then report. `where`
# labels the failure message: the same invariant is checked in three places, and a
# failure has to say WHICH of them broke.
assert_key_modes() {
  local dir="$1" where="$2" m kp km n=0
  [[ -d "$dir" ]] || fail "$where: no keys/ directory at $dir"
  m="$(mode_of "$dir")"
  [[ "$m" == "700" ]] || fail "$where: keys/ must be 0700, got 0$m"
  for kp in "$dir"/committee-*.key; do
    [[ -e "$kp" ]] || fail "$where: keys/ holds no committee-*.key"
    km="$(mode_of "$kp")"
    [[ "$km" == "600" ]] || fail "$where: $(basename "$kp") must be 0600, got 0$km"
    n=$((n + 1))
  done
  pass "$where: keys/ 0700, all $n key files 0600"
}

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

  # 2c. key material modes, DIRECTORY as well as files. `genesis init` writes 0700/0600
  #     and both deploy transports preserve modes, so this is the mode the live hosts
  #     get. `node_root` itself is deliberately NOT asserted: it holds only public
  #     material (genesis.qmb, node.toml, the binary, data/), it is left at the
  #     operator's umask by design, and pinning it to 0755 here would fail for anyone
  #     deploying under a tighter umask — a test that can fail on umask alone is worse
  #     than no test.
  assert_key_modes "$root/keys" "$name deployed"

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

# ---- pass 2: the creation site, and a re-deploy over a loosened tree ---------
#
# Everything above inspects a COPY of the staging tree. Two failures it cannot see:
#
#   (a) a mode fixed on the copy instead of at the stage. `--keep-stage` keeps the
#       staging tree and deploy.sh prints its path, so the modes can be asserted
#       where they are set rather than one transport downstream.
#   (b) a re-deploy onto a tree the PRE-FIX script laid down. `rsync -a --delete`
#       (real hosts) rewrites an existing directory's mode; `cp -R` (local mode)
#       does not — so without an explicit mode on the destination, a 0755 keys/
#       would survive every future local deploy while the remote path self-repaired.
#
# Loosen all four keys/ to 0755 first: that is exactly the state the live net was
# found in on 2026-07-31, so this pass fails on an unfixed script and passes on a
# fixed one.
echo "== pass 2: staged modes + re-deploy over a loosened tree =="
for name in "${NODES[@]}"; do
  chmod 755 "$BASE/nodes/$name/keys"
  [[ "$(mode_of "$BASE/nodes/$name/keys")" == "755" ]] \
    || fail "$name: could not loosen keys/ to 0755 to set up the re-deploy check"
done
pass "loosened all 4 keys/ to 0755 (the state the live net was found in)"

"$SCRIPT_DIR/deploy.sh" \
  --hosts "$HOSTS" \
  --local-base "$BASE/nodes" \
  --metrics-port 9090 \
  --binary "$BINARY" \
  --keep-stage > "$BASE/redeploy.log"
STAGE="$(awk '/^ *stage: /{print $2}' "$BASE/redeploy.log")"
[[ -n "$STAGE" && -d "$STAGE/stage" ]] \
  || fail "deploy.sh --keep-stage reported no usable stage path (got '${STAGE:-}')"
pass "re-deploy complete, stage kept at $STAGE"

for i in "${!NODES[@]}"; do
  name="${NODES[$i]}"
  assert_key_modes "$STAGE/stage/$name/keys" "$name staged"
  assert_key_modes "$BASE/nodes/$name/keys" "$name re-deployed"
done

echo "== DRY-RUN PASSED =="
echo "genesis hash: $base_hash"
[[ "$KEEP" -eq 1 ]] && echo "tree kept at: $BASE"
exit 0
