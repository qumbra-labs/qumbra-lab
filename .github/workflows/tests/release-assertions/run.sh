#!/usr/bin/env bash
# Offline validation for the release lane's artifact gate
# (../../scripts/assert-release-artifacts.sh, used by ../../release-binaries.yml).
#
# WHY THIS EXISTS — the same argument as ../explorer-provenance/, one step sharper.
# The step under test runs only inside a release cut, which means a paid arm64
# runner, a 10x-billed macOS runner, and a publish to a PUBLIC repository. Its whole
# job is to REFUSE a bad artifact, so the interesting cases are the ones where it
# must fail — and there is no way to make a real release build produce a drifted
# frozen digest on demand. Exercising the refusals against captured `halt-status`
# output is the only way they are ever tested at all.
#
# The two positive fixtures are REAL captured output, not hand-written: an armed
# and a resume `qumbra-node` built from this tree on 2026-08-17 (macOS arm64, debug,
# QUMBRA_BUILD_REV=deadbeefcafe). The negatives are those files with exactly one
# field edited, so each test names one defect and nothing else.
#
# NOT WIRED INTO ANY WORKFLOW. It costs nothing until a human runs it:
#
#     .github/workflows/tests/release-assertions/run.sh
#
# Requires: bash. No network, no docker, no cargo, no credential.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixtures"
GATE="$HERE/../../scripts/assert-release-artifacts.sh"
WORKFLOW="$HERE/../../release-binaries.yml"
NODE_IMAGE="$HERE/../../node-image.yml"

BUILD_REV=deadbeefcafe
PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Stubs. `assert-release-artifacts.sh` reaches its subjects only through
# `$NODE_BIN halt-status` and `$WALLET_BIN --help`, so a fixture-printing script
# is a faithful stand-in for a built binary — which is the whole reason the gate
# is a script and not inline YAML.
# ---------------------------------------------------------------------------
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# $1 = fixture, $2 = build rev to substitute, $3 = baked net, $4 = baked genesis
# hash. An EMPTY $3 stands for a binary from before lab #527: it has no
# `--print-net` and refuses the flag, which is what every published binary up to
# and including t2-644a129 does.
make_node_stub() {
  local out="$TMP/qumbra-node-stub"
  {
    echo '#!/usr/bin/env bash'
    echo "if [ \"\${1:-}\" = mine ] && [ \"\${2:-}\" = --print-net ]; then"
    if [ -n "${3:-}" ]; then
      echo "  echo 'qumbra-node mine — baked network identity'"
      echo "  echo 'net: $3'"
      echo "  echo 'genesis hash: $4'"
      echo "  echo 'genesis url: https://seed.qumbra.org/genesis.qmb'"
      echo "  echo 'seeds: 18.202.166.126:9444'"
      echo "  echo 'pin source: stamped into this binary by the release lane for net $3'"
      echo "  exit 0"
    else
      echo "  echo 'mine: unknown flag --print-net' >&2"
      echo "  exit 1"
    fi
    echo "fi"
    echo "[ \"\${1:-}\" = halt-status ] || { echo \"stub: unexpected args: \$*\" >&2; exit 64; }"
    echo "sed 's/BUILDREV/$2/' '$1'"
    # A release that refuses to start exits non-zero from halt-status; the fixture
    # name is the only thing that says so, so the stub keys on it.
    case "$1" in *refuses*) echo "exit 1" ;; esac
  } > "$out"
  chmod +x "$out"
  echo "$out"
}

make_wallet_stub() { # $1 = build rev line value, $2 = the net it was baked for
  local out="$TMP/qumbra-wallet-stub"
  {
    echo '#!/usr/bin/env bash'
    # usage() order, from crates/qumbra-wallet/src/main.rs: stamp, then net, then
    # the usage body. lab #581 added the `built for net:` line and the gate's
    # assertion for it, and did NOT add it here — so every case in this file was
    # failing on the wallet before it reached anything else (found in lab #636).
    echo "echo \"build rev: $1\""
    echo "echo \"built for net: $2\""
    echo 'echo "qumbra-wallet — the end-user wallet CLI (issue #243)"'
  } > "$out"
  chmod +x "$out"
  echo "$out"
}

make_pool_stub() { # $1 = build rev line value
  local out="$TMP/qumbra-pool-stub"
  {
    echo '#!/usr/bin/env bash'
    # 🔴 THE SHAPE IS THE TEST (lab #636). qumbra-pool's usage() prints a NINE-line
    # block and then a SECOND eprintln! with the stamp, so `build rev:` is on line
    # 10 — and the gate read `sed -n '1,8p'`. The window and the stamp shipped in
    # one commit (1c995e4), so the assertion never passed once; a draft release cut
    # from 8b347ce6 died on it. This stub printed three lines and no stamp at all,
    # which is why this file could not have caught it. Keep the line count exact:
    # if usage() grows a line, this stub must grow the same line.
    # All of it on STDERR, as usage() does; the gate reads it with 2>&1.
    echo 'exec >&2'
    echo 'echo "qumbra-pool — the T2 pool listener (lab #482 stage 1)"'   #  1
    echo 'echo ""'                                                        #  2
    echo 'echo "USAGE:"'                                                  #  3
    echo 'echo "  qumbra-pool check --config FILE   validate config; bind nothing"'  # 4
    echo 'echo "  qumbra-pool run --config FILE     listen for stratum TCP"'         # 5
    echo 'echo ""'                                                        #  6
    echo 'echo "v4-compat: a v4 template refuses stock-xmrig login by name"'          # 7
    echo 'echo "  (#356 UNCLEAN). Share-PoW: qlab_pow::RandomXHasher. PPLNS + N=1 payee list."'  # 8
    echo 'echo ""'                                                        #  9
    echo "echo \"build rev: $1\""                                        # 10
  } > "$out"
  chmod +x "$out"
  echo "$out"
}

# The net the lane is cutting, and the hash its preflight measured off the
# genesis actually being served. Same values as select-release-net.sh; the pin
# checks at the bottom are what stop this copy going stale.
CUT_NET=t2
T1_HASH=138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb
T2_HASH=d1dad4ea2bc5bfc4880ecf25206d182cddeacc12b0f65eca1a1ce2f27a93e2f3

# expect <want:pass|fail> <name> <node-fixture> <node-rev> <wallet-rev>
#        [baked-net] [baked-hash] [pool-rev] [wallet-net]
# Everything after <wallet-rev> defaults to a correct binary, so a case only
# states the ONE field it is about. [baked-net]/[baked-hash] describe what `mine`
# baked (an EMPTY baked-net is a pre-lab-#527 binary that cannot answer at all);
# [pool-rev] is the pool's stamp (lab #605/#636); [wallet-net] is the wallet's
# `built for net:` (lab #581).
expect() {
  local want=$1 name=$2 fixture=$3 nrev=$4 wrev=$5
  local bnet=${6-$CUT_NET} bhash=${7-$T2_HASH}
  local prev=${8-$BUILD_REV} wnet=${9-$CUT_NET}
  local node wallet pool out rc
  node=$(make_node_stub "$FIX/$fixture" "$nrev" "$bnet" "$bhash")
  wallet=$(make_wallet_stub "$wrev" "$wnet")
  pool=$(make_pool_stub "$prev")
  out=$(cd "$TMP" && NODE_BIN="$node" WALLET_BIN="$wallet" POOL_BIN="$pool" \
        EXPECTED_BUILD_REV="$BUILD_REV" \
        NET="$CUT_NET" GENESIS_HASH="$T2_HASH" \
        FROZEN_PIN=a54e73ce3d1c4fe9984d06b08f99b7577ed1db452b87abd712cf85ce5f3e7b5b \
        EXPECTED_REVISION=v1.1-exact-emission \
        EXPECTED_DOMAIN=56447169ab09956fcb78e8fb79a7cf2b502bd42194960226f83da2fb64db20b0 \
        RULE_BOUNDARY_HEIGHT=8640 \
        bash "$GATE" 2>&1)
  rc=$?
  local got=pass; [ $rc -eq 0 ] || got=fail
  if [ "$got" = "$want" ]; then
    PASS=$((PASS + 1)); echo "  ok   $name (expected $want)"
  else
    FAIL=$((FAIL + 1)); echo "  FAIL $name — expected $want, got $got"; echo "$out" | sed 's/^/       | /'
  fi
}

echo "release-assertions: the gate accepts exactly one thing and refuses the rest"

# The one artifact that may be published.
expect pass "a stamped resume build" halt-status-resume.txt "$BUILD_REV" "$BUILD_REV"

# 🔴 The refusal this file exists for. #397: an armed binary reaching a deployed
# artifact froze the public faucet at 8,640 for ~24 h. A published armed tarball
# would do the same to every stranger who downloads it, with no operator able to fix it.
expect fail "an ARMED build (a bare cargo build)" halt-status-armed.txt "$BUILD_REV" "$BUILD_REV"

# The dual of the emission check since #367's no-halt crossing: a binary whose NAME
# service is inert forks silently at 19,009 and must not ship (run 32011357820's
# lesson inverted — "ARMED" on the name line is required, not poison).
expect fail "a name-inert build (pre-135078c tree)" halt-status-name-inert.txt "$BUILD_REV" "$BUILD_REV"

# Frozen-digest drift, both halves — the declared value and the one recomputed from
# the binary's own constants. node-image.yml checks both because they fail
# differently: a stale revision string vs constants that moved under it.
expect fail "declared frozen digest drifted" halt-status-declared-drift.txt "$BUILD_REV" "$BUILD_REV"
expect fail "recomputed frozen digest drifted" halt-status-recomputed-drift.txt "$BUILD_REV" "$BUILD_REV"

# Provenance. An unstamped or wrongly-stamped binary is publishable-looking and
# untraceable — the exact gap a tarball has and an OCI-labelled image does not.
expect fail "the node ignored QUMBRA_BUILD_REV" halt-status-unstamped.txt "$BUILD_REV" "$BUILD_REV"
expect fail "the node carries a different revision" halt-status-resume.txt someotherrev "$BUILD_REV"
expect fail "the wallet is from a different build" halt-status-resume.txt "$BUILD_REV" someotherrev

# 🔴 Lab #636, the regression this file was blind to. The pool's stamp is on line
# 10 of --help and the gate read the first EIGHT lines, so a correctly stamped
# pool was refused with "the field or its format moved". The positive case above
# now covers the pass side (the stub's stamp is on line 10 and must be read), and
# these two cover the refusals — the point being that widening the reader must not
# turn this into a check that passes on anything.
#
# `unstamped — not built by the release lane` MATCHES `^build rev: ` and satisfies
# the gate's `[ -n "$POOL_REV" ]` guard. What refuses it is the equality check
# against EXPECTED_BUILD_REV that follows. This case is the proof that the guard
# is a message, not the assertion — the question lab #636 asked us to answer.
expect fail "the pool ignored QUMBRA_BUILD_REV" halt-status-resume.txt \
       "$BUILD_REV" "$BUILD_REV" "$CUT_NET" "$T2_HASH" "unstamped — not built by the release lane"
# The pool is the binary whose assemble_coinbase decides who gets paid, so "which
# build paid this miner" must be answerable from the tarball it shipped in.
expect fail "the pool is from a different build" halt-status-resume.txt \
       "$BUILD_REV" "$BUILD_REV" "$CUT_NET" "$T2_HASH" someotherrev

# Lab #581's own assertion had no coverage here either — the stub could not
# produce a wrong net because it produced no net line at all. A wallet baked for
# the retired net derives a T2 miner's coinbase under T1's genesis form: the note
# reads as spendable and refuses at the witness lookup.
expect fail "the wallet is baked for the retired net" halt-status-resume.txt \
       "$BUILD_REV" "$BUILD_REV" "$CUT_NET" "$T2_HASH" "$BUILD_REV" t1

# 🔴 Lab #527, reproduced at the gate. The T2 release shipped a binary whose
# `mine` baked T1's genesis hash: it downloaded the correct T2 genesis and
# refused it, breaking the path the public join guide advertises as THE
# one-command solo route, four hours into T2. Every other assertion in this file
# passed on that artifact, because every other assertion exercises the config
# path and `mine` writes its own config from compiled-in constants.
expect fail "the shipped T2 defect: mine baked for t1" halt-status-resume.txt \
       "$BUILD_REV" "$BUILD_REV" t1 "$T1_HASH"
# The same defect with the label right and only the number wrong — a build told
# the net but not given QUMBRA_GENESIS_HASH, or whose net table went stale.
expect fail "right net, wrong genesis pin" halt-status-resume.txt \
       "$BUILD_REV" "$BUILD_REV" t2 "$T1_HASH"
# A binary from before this check existed cannot answer the question, and an
# unanswerable question is a refusal rather than a skip: every such binary bakes
# exactly one net.
expect fail "a pre-#527 binary with no --print-net" halt-status-resume.txt \
       "$BUILD_REV" "$BUILD_REV" "" ""

# `halt-status` exits non-zero when the release refuses to start. The gate must
# carry that through `| tee` — this is a `pipefail` regression test, and the same
# construct's absence is what lab #428 turned on in the sibling workflow.
expect fail "a release that refuses to start" halt-status-refuses.txt "$BUILD_REV" "$BUILD_REV"

# ---------------------------------------------------------------------------
# Pin tests. The values above are duplicated from the workflow's env block, and a
# duplicated pin is a pin that goes stale silently — which is the failure this
# project has paid for more than any other.
# ---------------------------------------------------------------------------
pin() { # $1 = name, $2 = file, $3 = grep -F pattern
  if grep -qF "$3" "$2"; then
    PASS=$((PASS + 1)); echo "  ok   pin: $1"
  else
    FAIL=$((FAIL + 1)); echo "  FAIL pin: $1 — '$3' not found in $(basename "$2")"
  fi
}
pin "FROZEN_PIN matches release-binaries.yml" "$WORKFLOW" \
    "FROZEN_PIN: a54e73ce3d1c4fe9984d06b08f99b7577ed1db452b87abd712cf85ce5f3e7b5b"
pin "EXPECTED_REVISION matches release-binaries.yml" "$WORKFLOW" \
    "EXPECTED_REVISION: v1.1-exact-emission"
pin "EXPECTED_DOMAIN matches release-binaries.yml" "$WORKFLOW" \
    "EXPECTED_DOMAIN: 56447169ab09956fcb78e8fb79a7cf2b502bd42194960226f83da2fb64db20b0"
pin "RULE_BOUNDARY_HEIGHT matches release-binaries.yml" "$WORKFLOW" \
    'RULE_BOUNDARY_HEIGHT: "8640"'

# Cross-file: the image lane and the release lane publish the SAME consensus binary
# by two routes. If their pins ever disagree, one of them is publishing something
# the other would refuse, and nothing else in the tree would notice.
pin "node-image.yml agrees on the frozen digest" "$NODE_IMAGE" \
    'FROZEN_PIN="a54e73ce3d1c4fe9984d06b08f99b7577ed1db452b87abd712cf85ce5f3e7b5b"'
pin "node-image.yml agrees on the resume rule domain" "$NODE_IMAGE" \
    'EXP_DOMAIN="56447169ab09956fcb78e8fb79a7cf2b502bd42194960226f83da2fb64db20b0"'

# Lab #516: the four T1-hardwired sites moved into select-release-net.sh. The
# workflow must still mention that script, and the T2 pin must live in it.
SELECT="$HERE/../../scripts/select-release-net.sh"
pin "workflow dispatches on net" "$WORKFLOW" \
    "id: pins"
pin "T2 genesis pin lives in select-release-net.sh" "$SELECT" \
    "T2_GENESIS_HASH=d1dad4ea2bc5bfc4880ecf25206d182cddeacc12b0f65eca1a1ce2f27a93e2f3"
pin "T1 genesis pin still reachable" "$SELECT" \
    "T1_GENESIS_HASH=138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb"
pin "cutover refusal text" "$SELECT" \
    "published genesis is still t1 — run this after the cutover"

# Lab #527: the net must reach the BUILD, not just the smoke and the packaging.
# Both stamps, because a hash with no net label cannot be checked back out, and
# a net label with no hash is what the shipped T2 binary effectively had.
pin "the build is stamped with the net" "$WORKFLOW" \
    "QUMBRA_NET: \${{ needs.preflight.outputs.net }}"
pin "the build is stamped with the genesis pin" "$WORKFLOW" \
    "QUMBRA_GENESIS_HASH: \${{ needs.preflight.outputs.genesis_hash }}"

# The node's own net table is the fourth copy of these pins, and the reason this
# section exists. mine.rs's the_net_table_is_the_release_lanes_net_table asserts
# the same agreement in Rust; this one costs no cargo, so it also covers the
# tree where the table was edited and the suite was not run.
MINE_RS="$HERE/../../../../crates/qumbra-node/src/mine.rs"
GATE_SH="$HERE/../../scripts/assert-release-artifacts.sh"
pin "mine.rs pins the same T2 genesis as the lane" "$MINE_RS" "$T2_HASH"
pin "mine.rs pins the same T1 genesis as the lane" "$MINE_RS" "$T1_HASH"
pin "mine.rs reads the net stamp" "$MINE_RS" "option_env!(\"QUMBRA_NET\")"
pin "the gate asks the artifact what net it is" "$GATE_SH" "mine --print-net"

echo ""
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
