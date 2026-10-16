#!/usr/bin/env bash
# Lab #937 cut-over (D-C6): build the HARNESS-ONLY kernel — qumbra-ffi with
# `harness-pins` (qmb_harness_pin_fixture over the fixture-pin registry) — for
# a shell's test harness to replay the recorder's paid format-34 cases.
#
# It is NEVER packaged: its own target directory (a release build's artifact
# is never overwritten), its own file name, and every harness export is named
# `qmb_harness_*`, which scripts/refuse-harness-wasm.sh refuses.
#
#   scripts/build-harness-wasm.sh <out-dir>   → <out-dir>/qumbra_ffi_harness.wasm
set -euo pipefail
OUT="${1:?usage: build-harness-wasm.sh <out-dir>}"
LAB="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="$LAB/target/harness-wasm"
REMAP="--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=$LAB=/lab"
( cd "$LAB" && RUSTFLAGS="--cfg getrandom_backend=\"wasm_js\" $REMAP" CARGO_TARGET_DIR="$TARGET_DIR" \
  cargo build --release --locked -p qumbra-ffi --features harness-pins --target wasm32-unknown-unknown )
mkdir -p "$OUT"
cp "$TARGET_DIR/wasm32-unknown-unknown/release/qumbra_ffi.wasm" "$OUT/qumbra_ffi_harness.wasm"
# Its own check, the packager's in reverse: this one must name the harness export.
if ! grep -q -a 'qmb_harness_pin_fixture' "$OUT/qumbra_ffi_harness.wasm"; then
  echo "build-harness-wasm: the artifact does not export qmb_harness_pin_fixture" >&2
  exit 1
fi
echo "harness kernel (NOT for packaging): $OUT/qumbra_ffi_harness.wasm"
