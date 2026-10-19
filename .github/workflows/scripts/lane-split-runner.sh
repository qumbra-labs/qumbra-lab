#!/usr/bin/env bash
# The acceptance lane's split (lab #977): a cargo TARGET RUNNER that decides,
# per test binary, which of the two suite jobs executes it.
#
#   CARGO_TARGET_<HOST>_RUNNER=lane-split-runner.sh   (set by the suite job)
#   env LANE_SPLIT        rest | proving — which half this job is
#       CARGO_PKG_NAME    set by cargo for every binary it runs (the Cargo
#                         book: the crate env vars "also apply for running
#                         binaries with cargo run and cargo test")
#
# WHY A RUNNER AND NOT `-p` / `--exclude` (CLAUDE.md §5). Cargo resolves
# features over the SELECTED packages only, so `--exclude qumbra-wallet`
# builds a different tree than the bar: measured on 19f4103d with
# `cargo tree -e normal,build,dev`, the excluded half loses `qlab-air`'s
# `audit` and `test-support`, `qumbra-node`'s wrapper test-knob feature and
# `qumbra-sequencer`'s `test-support` — features that gate tests. That is the
# crate-scoped filter §5 forbids, one level down. A runner changes nothing
# about the build: both jobs run the bar's own `cargo test --release
# --workspace`, compile the same binaries with the same features from the
# same warm cache, and only the EXECUTION of each binary is assigned.
#
# A binary of the other half is still executed, with a filter that matches
# no test, so libtest itself writes `test result: ok. 0 passed; 0 failed;
# 0 ignored; 0 measured; N filtered out`. Every binary therefore reports in
# both jobs (the completeness denominator is unchanged), and the halves
# cross-check: this job's `filtered out` total is the other job's
# passed + failed + ignored over the same binaries.
#
# THE ONE LIST. `PROVING` below is the only place the split is written; the
# other half is its complement by construction, so no binary can fall
# between the jobs or run in both. Chosen from the per-package lane minutes
# of runs 39234060268 / 39234789040 (2026-10-19): qlab-bench 27.4 (one
# binary) + qumbra-wallet 22–26 (the Annulet proving integration tests) —
# the packages new proving tests land in.
#
# Loud on every unexpected input (exit 101, cargo's own test-failure code):
# a missing CARGO_PKG_NAME or an unknown LANE_SPLIT must turn the suite red,
# never quietly run everything twice or nothing at all.
set -uo pipefail

PROVING="qlab-bench qumbra-wallet"

bin="${1:?lane-split-runner: no binary given (cargo passes it as the first argument)}"
shift

pkg="${CARGO_PKG_NAME:-}"
if [ -z "$pkg" ]; then
  echo "lane-split-runner: CARGO_PKG_NAME is unset for $bin — cannot assign it to a half; refusing" >&2
  exit 101
fi

in_proving=0
for p in $PROVING; do
  [ "$p" = "$pkg" ] && in_proving=1
done

case "${LANE_SPLIT:-}" in
  proving) here=$in_proving ;;
  rest) here=$((1 - in_proving)) ;;
  *)
    echo "lane-split-runner: LANE_SPLIT is '${LANE_SPLIT:-}', not rest or proving — refusing" >&2
    exit 101
    ;;
esac

if [ "$here" = 1 ]; then
  exec "$bin" "$@"
fi
echo "lane-split: $pkg runs in the other half; filtered here"
exec "$bin" "$@" --exact "lane-split: runs in the other half"
