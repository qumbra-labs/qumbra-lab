#!/usr/bin/env bash
# Net dispatch for the release lane (lab #516).
#
# One file, two nets — not a fork of release-binaries.yml. `NET=t1|t2` (default
# t2) selects the four sites that were hardwired to T1:
#
#   1. tag prefix          t1- / t2-
#   2. GENESIS_HASH        the keccak256 of the published genesis.qmb
#   3. smoke expectations  (the smoke script reads GENESIS_HASH / DIAL_PEERS)
#   4. DIAL_PEERS          the four public fleet IPs — same hosts on both nets
#                          (sanity-checked 2026-08-20 against mine.rs T1_SEEDS
#                          and the T1 join path; T2 keeps the hosts, cutover
#                          repoints the bare names)
#
# THE ORDERING CONSTRAINT, stated here because the smoke verifies against the
# PUBLISHED genesis at https://seed.qumbra.org/genesis.qmb, whose bare name
# moves from T1 to T2 at cutover (naming §7 as amended). A T2 release can only
# be cut AFTER that cutover. This script fetches the live file, keccak256s it
# the same way GenesisFile::hash does, and refuses by name if the hash is not
# the pin for the selected net. The T2-before-cutover refusal is:
#
#   published genesis is still t1 — run this after the cutover
#
# Inputs:
#   NET              t1 | t2   (required; no silent default in the script —
#                                the workflow default lives on the dispatch input)
#   GENESIS_URL      required unless HASH_OVERRIDE is set
#   GENESIS_FILE     optional local path; skip the fetch
#   HASH_OVERRIDE    optional 64-hex; skip fetch AND keccak (offline tests)
#   GITHUB_OUTPUT    optional; when set, write pins as workflow outputs
#
# Prints the pins on stdout always. Exits 1 on a pin mismatch.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KECCAK="$HERE/keccak256.py"

T1_GENESIS_HASH=740ba41c06f1c0075e203380b9adc46cfbe84b4b28907f531254a90a2d8e518e
T2_GENESIS_HASH=59d9f054bb15116dac40c42ddb67c7d377407eec3010e9f98a5cc76e9e0544b1
# Same four public entry points T1 used (node0 is deliberately not one of them).
# Lab #516: the hosts stay; the genesis they serve is what the cutover changes.
DIAL_PEERS_BOTH='["18.202.166.126:9444","18.141.177.109:9444","52.194.224.123:9444","52.5.0.21:9444"]'
GENESIS_URL_DEFAULT=https://seed.qumbra.org/genesis.qmb

fail() { echo "::error::$*" >&2; echo "$*" >&2; exit 1; }

NET="${NET:-}"
[ -n "$NET" ] || fail "NET is required (t1 or t2)"

case "$NET" in
  t1)
    TAG_PREFIX=t1
    EXPECTED_HASH="$T1_GENESIS_HASH"
    ;;
  t2)
    TAG_PREFIX=t2
    EXPECTED_HASH="$T2_GENESIS_HASH"
    ;;
  *) fail "NET must be t1 or t2, got '$NET'" ;;
esac

DIAL_PEERS="$DIAL_PEERS_BOTH"
GENESIS_URL="${GENESIS_URL:-$GENESIS_URL_DEFAULT}"

# ---------------------------------------------------------------------------
# Fetch + keccak, unless an offline test injected the hash.
# ---------------------------------------------------------------------------
GOT_HASH="${HASH_OVERRIDE:-}"
WORK=""
cleanup() {
  if [ -n "${WORK:-}" ] && [ -d "$WORK" ]; then
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

if [ -z "$GOT_HASH" ]; then
  WORK="$(mktemp -d)"
  FILE="${GENESIS_FILE:-$WORK/genesis.qmb}"
  if [ -z "${GENESIS_FILE:-}" ]; then
    [ -n "$GENESIS_URL" ] || fail "GENESIS_URL is required"
    echo "fetching published genesis from $GENESIS_URL"
    if ! curl -fsSL --retry 5 --retry-delay 5 --max-time 120 "$GENESIS_URL" -o "$FILE"; then
      fail "could not download $GENESIS_URL. Cannot tell which net the seed host is serving, so a release cannot be cut."
    fi
  fi
  [ -f "$FILE" ] || fail "genesis file not found: $FILE"
  ls -l "$FILE" >&2 || true
  GOT_HASH="$(python3 "$KECCAK" "$FILE")"
fi

GOT_HASH="$(printf '%s' "$GOT_HASH" | tr 'A-F' 'a-f')"
echo "published genesis keccak256: $GOT_HASH"
echo "expected for net=$NET:        $EXPECTED_HASH"

if [ "$GOT_HASH" != "$EXPECTED_HASH" ]; then
  if [ "$NET" = t2 ] && [ "$GOT_HASH" = "$T1_GENESIS_HASH" ]; then
    fail "published genesis is still t1 — run this after the cutover"
  fi
  if [ "$NET" = t1 ] && [ "$GOT_HASH" = "$T2_GENESIS_HASH" ]; then
    fail "published genesis is t2 — a T1 recut needs the T1 genesis at this URL (the bare name moved at cutover)"
  fi
  fail "published genesis hash $GOT_HASH is not the pin for net=$NET ($EXPECTED_HASH). Neither the t1 nor the t2 pin — stop and look."
fi

echo "genesis pin: OK for net=$NET"

# ---------------------------------------------------------------------------
# Pins, as workflow outputs when running inside Actions, and always as
# `key=value` lines on stdout so a dry local run is readable.
# ---------------------------------------------------------------------------
emit() {
  local k=$1 v=$2
  echo "$k=$v"
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s=%s\n' "$k" "$v" >> "$GITHUB_OUTPUT"
  fi
}

emit net "$NET"
emit tag_prefix "$TAG_PREFIX"
emit genesis_url "$GENESIS_URL"
emit genesis_hash "$EXPECTED_HASH"
emit dial_peers "$DIAL_PEERS"
