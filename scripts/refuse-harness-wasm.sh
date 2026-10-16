#!/usr/bin/env bash
# Lab #937 cut-over (D-C6): a packager's gate. Exit 1 if any given .wasm names
# a harness-only export (`qmb_harness_`, qumbra-ffi's `harness-pins` feature),
# 0 if none does. A release kernel never carries one; the harness kernel
# (scripts/build-harness-wasm.sh) always does.
#
#   scripts/refuse-harness-wasm.sh <file.wasm>...
set -euo pipefail
[ "$#" -ge 1 ] || { echo "usage: refuse-harness-wasm.sh <file.wasm>..." >&2; exit 2; }
bad=0
for f in "$@"; do
  [ -f "$f" ] || { echo "refuse-harness-wasm: $f: no such file" >&2; exit 2; }
  if grep -q -a 'qmb_harness_' "$f"; then
    echo "REFUSED: $f exports a harness-only symbol (qmb_harness_*): it is the harness kernel, never packaged" >&2
    bad=1
  fi
done
exit "$bad"
