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

make_node_stub() { # $1 = fixture, $2 = build rev to substitute
  local out="$TMP/qumbra-node-stub"
  {
    echo '#!/usr/bin/env bash'
    echo "[ \"\${1:-}\" = halt-status ] || { echo \"stub: unexpected args: \$*\" >&2; exit 64; }"
    echo "sed 's/BUILDREV/$2/' '$1'"
    # A release that refuses to start exits non-zero from halt-status; the fixture
    # name is the only thing that says so, so the stub keys on it.
    case "$1" in *refuses*) echo "exit 1" ;; esac
  } > "$out"
  chmod +x "$out"
  echo "$out"
}

make_wallet_stub() { # $1 = build rev line value
  local out="$TMP/qumbra-wallet-stub"
  {
    echo '#!/usr/bin/env bash'
    echo "echo \"build rev: $1\""
    echo 'echo "qumbra-wallet — the end-user wallet CLI (issue #243)"'
  } > "$out"
  chmod +x "$out"
  echo "$out"
}

# expect <want:pass|fail> <name> <node-fixture> <node-rev> <wallet-rev>
expect() {
  local want=$1 name=$2 fixture=$3 nrev=$4 wrev=$5
  local node wallet out rc
  node=$(make_node_stub "$FIX/$fixture" "$nrev")
  wallet=$(make_wallet_stub "$wrev")
  out=$(cd "$TMP" && NODE_BIN="$node" WALLET_BIN="$wallet" \
        EXPECTED_BUILD_REV="$BUILD_REV" \
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

echo ""
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
