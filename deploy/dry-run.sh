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
#      from, and again after a re-deploy over a deliberately loosened tree,
#   6. each host's `miner_rkm` from the hosts file reaches THAT node's config,
#      verbatim and alone, and SURVIVES REGENERATION (lab #475 acceptance (f) /
#      the standing 🔴 of OPERATOR §9.5.1),
#   7. a MINING fleet with a keyless host is REFUSED at generation — before the
#      build, the genesis or any payload — naming every keyless host and the
#      --no-mining exit (lab #552 / PR #655: the binary refuses that config, so
#      the generator must not produce it),
#   8. `--no-mining` still generates a mixed fleet cleanly: every node preflights
#      with mining = false, and a key given to one non-mining host reaches only it.
#
# Why (5) is three assertions and not one: the defect it guards against left every
# key FILE correctly 0600 and only the enclosing DIRECTORY world-searchable, so a
# file-mode check passed while four public-IP hosts ran `drwxr-xr-x /opt/qumbra/keys`.
# Asserting the deployed copy alone would also pass for a fix applied to the copy
# instead of the stage, and a fresh-tree assertion cannot see that `cp -R` leaves an
# existing directory's mode alone where `rsync -a` rewrites it.
#
# Why (7) and (8) are two passes and not one: since lab #552 the ONLY legal home
# for a host with no `miner_rkm` is a fleet that does not mine, so the mixed
# fleet that used to be this script's main fixture is now two fixtures — the one
# the generator must refuse, and the one it must still accept under --no-mining.
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
    -h|--help) sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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

# ---- fixtures ---------------------------------------------------------------
#
# The MINING fleet (ssh target "-" = local dir): every host carries its own payout
# key, all four DISTINCT. "node2's config carries node2's key and nobody else's"
# is a stronger routing assertion than the old "node2 carries no key" — a
# generator that wrote node1's key to all four hosts passed the old shape and
# fails this one. Illustrative values: the node accepts any non-zero 64-hex, and
# nothing spends what a dry-run mines (it mines nothing; `check` binds nothing).
rkm_of() {   # rkm_of <node index 0-9>: 63 hex digits of motif + the index
  printf 'dec1a2eddec1a2eddec1a2eddec1a2eddec1a2eddec1a2eddec1a2eddec1a2e%01d\n' "$1"
}
HOSTS="$BASE/hosts.local"
cat > "$HOSTS" <<EOF
# name  public_addr        ssh_target(-=local)   miner_rkm
node0   127.0.0.1:9401     -                     $(rkm_of 0)
node1   127.0.0.1:9402     -                     $(rkm_of 1)
node2   127.0.0.1:9403     -                     $(rkm_of 2)
node3   127.0.0.1:9404     -                     $(rkm_of 3)
EOF

# The MIXED fleet — node1 keyed, node0/node2 "-", node3 omitted (both spellings
# of "none"). This was the main fixture until lab #552, and the reason it existed
# still holds under --no-mining: the defect (the field simply not being emitted)
# looks identical to "this host has none" on any host that legitimately has
# none, so the one keyed host is what tells "emitted for the right host" from
# "not emitted". Under the default (mining) it is what pass 3 must refuse.
MIXED_HOSTS="$BASE/hosts.mixed"
MIXED_RKM="0100000000000000020000000000000003000000000000000400000000000000"
cat > "$MIXED_HOSTS" <<EOF
# name  public_addr        ssh_target(-=local)   miner_rkm
node0   127.0.0.1:9401     -                     -
node1   127.0.0.1:9402     -                     $MIXED_RKM
node2   127.0.0.1:9403     -                     -
node3   127.0.0.1:9404     -
EOF

# (6) as one assertion per host: the config carries exactly ONE miner_rkm line and
# it is this host's own key — so a key emitted to the wrong host, to every host, or
# twice all fail here, naming the host. `where` labels the pass so the deploy and
# the re-deploy are told apart.
assert_own_miner_rkm() {
  local where="$1" i name root n
  for i in 0 1 2 3; do
    name="node$i"; root="$BASE/nodes/$name"
    n="$(grep -c '^miner_rkm' "$root/node.toml" || true)"
    [[ "$n" -eq 1 ]] || fail "$where: $name carries $n miner_rkm lines, want exactly 1"
    grep -q "^miner_rkm = \"$(rkm_of "$i")\"\$" "$root/node.toml" \
      || fail "$where: $name's own miner_rkm did not reach its config verbatim (this is OPERATOR §9.5.1)"
  done
  pass "$where: each of the 4 hosts carries its own miner_rkm, verbatim and alone"
}

# `qumbra-node check` on a laid-down node, captured with `||` so a REFUSING binary
# fails the assertion BY NAME. A bare `out="$(...)"` trips `set -e` inside the
# substitution and exits with no FAIL line at all — which is how the lab #552
# regression first surfaced here: the binary's own ERROR and `exit 1`, and
# nothing saying which of the four hosts it was.
preflight_of() {   # preflight_of <label> <node_root>  -> stdout: the check output
  local label="$1" root="$2" out
  out="$("$root/qumbra-node" check --config "$root/node.toml" 2>&1)" \
    || fail "$label: the binary REFUSED this config —"$'\n'"$out"
  echo "$out" | grep -q 'check: OK' || fail "$label: preflight did not pass:"$'\n'"$out"
  echo "$out"
}

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

  # 5. real preflight via the deployed binary (bind nothing). Since lab #552 the
  #    binary REFUSES a mining node with no payout key, so a `check: OK` here is
  #    also the proof that the generator gave this mining host one — asserted
  #    explicitly too: the binary must report mining = true AND this host's key,
  #    so a grep on the config is not the only thing agreeing with the hosts file.
  out="$(preflight_of "$name" "$root")"
  h="$(echo "$out" | awk '/genesis hash:/{print $NF}')"
  kh="$(echo "$out" | awk '/keys held:/{print $NF}')"
  [[ "$kh" -eq "${EXPECT_KEYS[$i]}" ]] || fail "$name: preflight keys-held $kh != ${EXPECT_KEYS[$i]}"
  echo "$out" | grep -q '^  mining:       true$' \
    || fail "$name: preflight does not report mining = true:"$'\n'"$out"
  echo "$out" | grep -q "^  miner_rkm:    $(rkm_of "$i")\$" \
    || fail "$name: preflight does not report this host's own payout key:"$'\n'"$out"
  HASHES+=("$h")
  pass "$name: qumbra-node check OK (keys held $kh, genesis $h, mining, payout key = its own)"
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

# 6. every host's payout key reached exactly the host that declared it. Asserted
#    after the FIRST deploy so a failure here is unambiguous — the re-deploy
#    below is what turns it into a round-trip claim.
assert_own_miner_rkm "deployed"

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

# 🔴 THE ROUND TRIP (lab #475 acceptance (f)). This is the assertion the whole
# column exists for: OPERATOR §9.5.1's standing red was that a RE-RUN dropped
# miner_rkm from every host that had it, so the generated config and the live
# config diverged permanently and the field was restored by hand after every
# deploy. On an unfixed script the first `assert_own_miner_rkm` already fails;
# this second one is what proves regeneration is idempotent rather than merely
# first-run-correct.
assert_own_miner_rkm "re-deployed"

# And still a config the node itself accepts, on every host — `preflight` parses
# miner_rkm with the node's own parser since lab #475, so this is not a grep
# agreeing with another grep.
for i in "${!NODES[@]}"; do
  name="${NODES[$i]}"
  out="$(preflight_of "$name re-deployed" "$BASE/nodes/$name")"
  echo "$out" | grep -q "^  miner_rkm:    $(rkm_of "$i")\$" \
    || fail "$name's regenerated config does not preflight with its own payout key:"$'\n'"$out"
done
pass "all 4 regenerated configs preflight, each payout key reported by the binary"

# ---- pass 3: a MINING fleet with keyless hosts is REFUSED at generation ------
#
# The binary refuses `mining = true` with no `miner_rkm` (lab #552 / PR #655). A
# generator that emitted it anyway would be caught one host at a time, on the
# host, after the rsync — or, in local mode, by (5) above. This pass pins the
# refusal to the generator itself: exit non-zero BEFORE the genesis is minted or
# any node directory exists; name EVERY keyless host in one message (lab #475:
# catch it once, not one host at a time) and not the keyed one; and point at
# --no-mining — the honest exit — rather than flipping the hosts itself.
echo "== pass 3: the mixed fleet is REFUSED when the fleet mines =="
REFUSED_LOG="$BASE/refused.log"
if "$SCRIPT_DIR/deploy.sh" --hosts "$MIXED_HOSTS" --local-base "$BASE/refused" \
     --binary "$BINARY" > "$REFUSED_LOG" 2>&1; then
  fail "deploy.sh GENERATED a mining fleet with keyless hosts (node0/node2/node3) — the binary refuses that config, so the generator must"
fi
pass "deploy.sh exited non-zero on a mining fleet with keyless hosts"
[[ ! -e "$BASE/refused" ]] \
  || fail "refusal came too late: $BASE/refused exists, so payloads were laid down first"
grep -q 'generating genesis' "$REFUSED_LOG" \
  && fail "refusal came too late: a genesis was minted first"
pass "refused before the genesis was minted or any payload was laid down"
for name in node0 node2 node3; do
  grep -qw "$name" "$REFUSED_LOG" \
    || fail "the refusal does not name keyless host $name:"$'\n'"$(cat "$REFUSED_LOG")"
done
grep -qw 'node1' "$REFUSED_LOG" && fail "the refusal names node1, which carries a key"
grep -q 'miner_rkm' "$REFUSED_LOG" || fail "the refusal does not name miner_rkm"
grep -q -- '--no-mining' "$REFUSED_LOG" || fail "the refusal does not point at --no-mining"
pass "refusal names node0 node2 node3 (not node1), miner_rkm, and the --no-mining exit"

# ---- pass 4: --no-mining still generates the mixed fleet, cleanly -------------
#
# The same hosts file, with the fleet told not to mine: the one regime in which a
# keyless host is legal since lab #552. Every node must preflight; the binary must
# report mining = false on each (so a rehearsal cannot mine by accident either);
# node1's key must reach node1 and only node1 — a non-mining node may carry a key
# ("legal unused"), and the source-of-truth property does not switch off with
# mining.
echo "== pass 4: --no-mining generates the mixed fleet and every node preflights =="
"$SCRIPT_DIR/deploy.sh" --hosts "$MIXED_HOSTS" --local-base "$BASE/nomining" \
  --binary "$BINARY" --no-mining > "$BASE/nomining.log"
pass "deploy.sh --no-mining accepted the mixed fleet"
for name in node0 node2 node3; do
  grep -q '^miner_rkm' "$BASE/nomining/$name/node.toml" \
    && fail "--no-mining: $name has no miner_rkm in the hosts file but its config carries one"
done
grep -q "^miner_rkm = \"$MIXED_RKM\"\$" "$BASE/nomining/node1/node.toml" \
  || fail "--no-mining: node1's miner_rkm did not reach its config (this is OPERATOR §9.5.1)"
for name in "${NODES[@]}"; do
  grep -q '^mining = false$' "$BASE/nomining/$name/node.toml" \
    || fail "--no-mining: $name's config does not say mining = false"
done
pass "--no-mining: mining = false on all 4; miner_rkm present on node1 only, verbatim"
for name in "${NODES[@]}"; do
  out="$(preflight_of "--no-mining $name" "$BASE/nomining/$name")"
  echo "$out" | grep -q '^  mining:       false$' \
    || fail "--no-mining: $name: preflight does not report mining = false:"$'\n'"$out"
  case "$name" in
    node1) want="  miner_rkm:    $MIXED_RKM" ;;
    *)     want="  miner_rkm:    not set" ;;
  esac
  echo "$out" | grep -q "^$want" \
    || fail "--no-mining: $name: preflight miner_rkm line is not '$want':"$'\n'"$out"
done
pass "--no-mining: all 4 nodes preflight with mining = false; node1 reports its key, the rest report none"

echo "== DRY-RUN PASSED =="
echo "genesis hash: $base_hash"
[[ "$KEEP" -eq 1 ]] && echo "tree kept at: $BASE"
exit 0
