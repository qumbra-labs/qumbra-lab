#!/usr/bin/env bash
# Offline tests for lab #516's net dispatch + ordering guard
# (../../scripts/select-release-net.sh). Not wired into any workflow; costs
# nothing until a human (or a builder) runs it:
#
#     .github/workflows/tests/release-net/run.sh
#
# Requires: bash, python3. No network — every case injects HASH_OVERRIDE so a
# machine that cannot reach seed.qumbra.org still proves the refusal text.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELECT="$HERE/../../scripts/select-release-net.sh"
KECCAK="$HERE/../../scripts/keccak256.py"

PASS=0
FAIL=0

echo "release-net: pins, keccak, and the cutover ordering guard"

# Keccak self-check against the tiny-keccak / pycryptodome empty-string vector
# (qlab_devnet::hash::keccak256_matches_tiny_keccak's shortest case).
EMPTY_WANT=c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
EMPTY_GOT="$(printf '' | python3 "$KECCAK")"
if [ "$EMPTY_GOT" = "$EMPTY_WANT" ]; then
  PASS=$((PASS + 1)); echo "  ok   keccak256(empty) matches tiny-keccak"
else
  FAIL=$((FAIL + 1)); echo "  FAIL keccak256(empty) — got $EMPTY_GOT want $EMPTY_WANT"
fi
ABC_WANT=4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
ABC_GOT="$(printf 'abc' | python3 "$KECCAK")"
if [ "$ABC_GOT" = "$ABC_WANT" ]; then
  PASS=$((PASS + 1)); echo "  ok   keccak256(abc) matches tiny-keccak"
else
  FAIL=$((FAIL + 1)); echo "  FAIL keccak256(abc) — got $ABC_GOT want $ABC_WANT"
fi

T1=138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb
T2=d1dad4ea2bc5bfc4880ecf25206d182cddeacc12b0f65eca1a1ce2f27a93e2f3

# The refusal this file exists for. Today (pre-cutover) the published file
# hashes to T1; a T2 dispatch must die on this sentence, not on a generic mismatch.
out="$(NET=t2 HASH_OVERRIDE=$T1 bash "$SELECT" 2>&1)" || true
if printf '%s\n' "$out" | grep -qF 'published genesis is still t1 — run this after the cutover'; then
  PASS=$((PASS + 1)); echo "  ok   t2 against t1 genesis refuses with the cutover sentence"
else
  FAIL=$((FAIL + 1)); echo "  FAIL t2-vs-t1 refusal text missing"; echo "$out" | sed 's/^/       | /'
fi

out="$(NET=t2 HASH_OVERRIDE=$T2 bash "$SELECT" 2>&1)"
rc=$?
if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -q '^tag_prefix=t2$' && printf '%s\n' "$out" | grep -q "^genesis_hash=$T2$"; then
  PASS=$((PASS + 1)); echo "  ok   t2 against t2 genesis emits t2- pins"
else
  FAIL=$((FAIL + 1)); echo "  FAIL t2 happy path (rc=$rc)"; echo "$out" | sed 's/^/       | /'
fi

out="$(NET=t1 HASH_OVERRIDE=$T1 bash "$SELECT" 2>&1)"
rc=$?
if [ $rc -eq 0 ] && printf '%s\n' "$out" | grep -q '^tag_prefix=t1$' && printf '%s\n' "$out" | grep -q "^genesis_hash=$T1$"; then
  PASS=$((PASS + 1)); echo "  ok   t1 against t1 genesis emits t1- pins (recut still reachable)"
else
  FAIL=$((FAIL + 1)); echo "  FAIL t1 happy path (rc=$rc)"; echo "$out" | sed 's/^/       | /'
fi

out="$(NET=t1 HASH_OVERRIDE=$T2 bash "$SELECT" 2>&1)" || true
if printf '%s\n' "$out" | grep -qF 'published genesis is t2 — a T1 recut needs the T1 genesis at this URL'; then
  PASS=$((PASS + 1)); echo "  ok   t1 against t2 genesis refuses by name"
else
  FAIL=$((FAIL + 1)); echo "  FAIL t1-vs-t2 refusal text missing"; echo "$out" | sed 's/^/       | /'
fi

out="$(NET=t2 HASH_OVERRIDE=deadbeefcafe bash "$SELECT" 2>&1)" || true
if printf '%s\n' "$out" | grep -qF 'is not the pin for net=t2'; then
  PASS=$((PASS + 1)); echo "  ok   unknown hash refuses rather than matching either net"
else
  FAIL=$((FAIL + 1)); echo "  FAIL unknown-hash refusal"; echo "$out" | sed 's/^/       | /'
fi

out="$(NET=t3 HASH_OVERRIDE=$T1 bash "$SELECT" 2>&1)" || true
if printf '%s\n' "$out" | grep -qF "NET must be t1 or t2"; then
  PASS=$((PASS + 1)); echo "  ok   a third net name is refused"
else
  FAIL=$((FAIL + 1)); echo "  FAIL NET=t3 should be refused"; echo "$out" | sed 's/^/       | /'
fi

# Both nets keep the same four fleet IPs (lab #516: hosts stay, genesis moves).
out="$(NET=t2 HASH_OVERRIDE=$T2 bash "$SELECT" 2>&1)"
if printf '%s\n' "$out" | grep -qF 'dial_peers=["18.202.166.126:9444","18.141.177.109:9444","52.194.224.123:9444","52.5.0.21:9444"]'; then
  PASS=$((PASS + 1)); echo "  ok   DIAL_PEERS is the four T1 public IPs"
else
  FAIL=$((FAIL + 1)); echo "  FAIL DIAL_PEERS"; echo "$out" | sed 's/^/       | /'
fi

echo ""
echo "passed $PASS, failed $FAIL"
[ "$FAIL" -eq 0 ]
