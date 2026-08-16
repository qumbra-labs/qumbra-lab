#!/usr/bin/env bash
# Offline validation for the "Read the provenance back from the registry" step
# of .github/workflows/explorer-image.yml.
#
# WHY THIS EXISTS: that step can only run on the PAID `qumbra-arm64-8` runner,
# after a build+push that costs ~$0.7 against a $20/month cap. Its bug (lab
# #428) was a readback that reported red on a genuinely-good, correctly-labelled
# publish. Spending a paid run to test the fix for a step that only ever runs
# after a paid run is the wrong trade, so the parsing and the assertion are
# validated here instead, against captured `imagetools inspect` output.
#
# NOT WIRED INTO ANY WORKFLOW. It costs nothing until a human runs it:
#
#     .github/workflows/tests/explorer-provenance/run.sh
#
# Requires: jq. No docker, no network, no registry credential.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixtures"
WORKFLOW="$HERE/../../explorer-image.yml"

command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 2; }

# ---------------------------------------------------------------------------
# The logic under test. This MUST stay byte-identical to the workflow step;
# `test_workflow_pin` below fails if it drifts.
# ---------------------------------------------------------------------------
JQ_EXTRACT='
            [ .. | objects | .Labels? // empty | objects
              | .["org.opencontainers.image.revision"]? // empty ]
            | map(select(type == "string" and . != "")) | unique | .[]'

# readback <image-json-file> <expected-sha> -> prints verdict, returns 0/1
readback() {
  local IMG GOT REVS
  IMG=$(cat "$1")
  local GITHUB_SHA="$2"

  REVS=$(printf '%s' "$IMG" | jq -r "$JQ_EXTRACT")

  if [ -z "$REVS" ]; then
    echo "::error::provenance unreadable -- the pushed image carries no org.opencontainers.image.revision label. This is NOT a mismatch verdict; the label could not be read at all."
    return 1
  fi
  if [ "$(printf '%s\n' "$REVS" | wc -l)" -gt 1 ]; then
    echo "::error::provenance mismatch -- platforms disagree on the revision label:"
    printf '%s\n' "$REVS" | sed 's/^/  /'
    return 1
  fi
  GOT="$REVS"

  if [ "$GOT" = "$GITHUB_SHA" ]; then
    echo "provenance OK: revision=$GOT"
  elif [ "${#GOT}" -ge 7 ] && [ "${GITHUB_SHA#"$GOT"}" != "$GITHUB_SHA" ]; then
    echo "::warning::the revision label is abbreviated ('$GOT'). It does name $GITHUB_SHA, so provenance holds, but the Dockerfile is meant to stamp the full sha."
    echo "provenance OK: revision=$GOT (abbreviated)"
  else
    echo "::error::provenance mismatch -- image revision '$GOT' != expected '$GITHUB_SHA'"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
EXPECTED=1400269f8ace841f8d0492f4f9c6c7f305f95268 # the revision the real fixtures carry
PASS=0
FAIL=0

# case <name> <fixture> <expected-sha> <want:ok|err> <substring the output must contain>
case_() {
  local name=$1 fixture=$2 sha=$3 want=$4 needle=$5 out rc
  out=$(readback "$FIX/$fixture" "$sha" 2>&1) && rc=0 || rc=1
  local got=ok; [ $rc -eq 0 ] || got=err
  if [ "$got" = "$want" ] && printf '%s' "$out" | grep -qF -- "$needle"; then
    printf '  PASS  %-34s %s\n' "$name" "$(printf '%s' "$out" | tail -1)"
    PASS=$((PASS + 1))
  else
    printf '  FAIL  %-34s want=%s/%s got=%s\n' "$name" "$want" "$needle" "$got"
    printf '%s\n' "$out" | sed 's/^/          /'
    FAIL=$((FAIL + 1))
  fi
}

echo "== the two real .Image shapes (captured from public registries) =="
# Both captured with:
#   docker buildx imagetools inspect <ref> --format '{{json .Image}}'
# from ghcr.io/open-telemetry/opentelemetry-collector-releases/opentelemetry-collector,
# an image built by GitHub Actions and carrying real OCI provenance labels.
case_ single-platform-object real-single-platform.json "$EXPECTED" ok "provenance OK"
case_ multi-platform-map     real-multi-platform.json  "$EXPECTED" ok "provenance OK"

echo "== shapes and outcomes not reachable from a public registry =="
case_ capital-Config-casing  synthetic-capital-config.json     "$EXPECTED" ok  "provenance OK"
case_ abbreviated-but-true   synthetic-abbreviated.json        "$EXPECTED" ok  "abbreviated"
case_ wrong-revision         synthetic-wrong-revision.json     "$EXPECTED" err "provenance mismatch"
case_ platforms-disagree     synthetic-platforms-disagree.json "$EXPECTED" err "provenance mismatch"
case_ label-absent           synthetic-no-label.json           "$EXPECTED" err "provenance unreadable"

echo "== mutation check: the assertion is load-bearing, not decorative =="
# Same good fixture, wrong expectation. If this passes, the step is asserting
# nothing and would green-light an image built from another commit.
case_ good-image-wrong-expect real-single-platform.json \
  0000000000000000000000000000000000000000 err "provenance mismatch"

echo "== regression: the pattern this step used to use =="
# The defect itself, reproduced on real bytes. buildx renders via
# json.MarshalIndent, so the label is `"...revision": "<sha>"` -- WITH a space.
# The old pattern had none, matched nothing, exited 1, and `set -o pipefail`
# carried that through `| head | sed` and failed the step after a good push.
if grep -o '"org.opencontainers.image.revision":"[0-9a-f]*"' "$FIX/real-single-platform.json" >/dev/null 2>&1; then
  echo "  FAIL  old-grep-pattern                 it matched -- the fixture does not reproduce #428"
  FAIL=$((FAIL + 1))
else
  echo "  PASS  old-grep-pattern                 no match (exit 1) on a good image == the #428 defect"
  PASS=$((PASS + 1))
fi
# ...and that the space is really there, rather than the fixture merely lacking
# the label for some other reason.
if grep -q '"org.opencontainers.image.revision": "' "$FIX/real-single-platform.json"; then
  echo "  PASS  space-after-colon-is-real        buildx emits '\": \"', the old pattern wanted '\":\"'"
  PASS=$((PASS + 1))
else
  echo "  FAIL  space-after-colon-is-real"
  FAIL=$((FAIL + 1))
fi

echo "== the workflow and this test have not drifted apart =="
test_workflow_pin() {
  # The jq program above is a copy of the workflow's. A copy that silently
  # diverges is worse than no test, so pin it.
  if grep -qF -- 'org.opencontainers.image.revision"]? // empty ]' "$WORKFLOW" &&
     grep -qF -- '| map(select(type == "string" and . != "")) | unique | .[]' "$WORKFLOW" &&
     grep -qF -- '[ .. | objects | .Labels? // empty | objects' "$WORKFLOW"; then
    echo "  PASS  jq-program-pinned-to-workflow"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  jq-program-pinned-to-workflow   explorer-image.yml no longer contains this jq program"
    FAIL=$((FAIL + 1))
  fi
}
test_workflow_pin

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
