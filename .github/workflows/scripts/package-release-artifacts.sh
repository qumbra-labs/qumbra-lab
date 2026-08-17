#!/usr/bin/env bash
# Packaging for the release lane (lab #437). One tarball per platform, holding the
# two binaries a joiner needs and a PROVENANCE.txt that keeps the archive
# self-describing after it has been copied off the release page.
#
# The per-file digest is computed HERE, on the machine that built the binary, and
# re-verified in the publish job after the artifact round trip — so a corrupted
# upload is caught rather than published under a digest computed from the corrupted
# file. `shasum -a 256` and `sha256sum` emit the same `<hash>  <name>` format, which
# is what lets the three platforms' fragments concatenate into one SHA256SUMS that
# `sha256sum -c` accepts.
set -euo pipefail

: "${PLATFORM:?PLATFORM is required}"
: "${TAG:?TAG is required}"
: "${LAB_REV:?LAB_REV is required}"

NODE_BIN="${NODE_BIN:-target/release/qumbra-node}"
WALLET_BIN="${WALLET_BIN:-target/release/qumbra-wallet}"

NAME="qumbra-${TAG}-${PLATFORM}"
rm -rf dist; mkdir -p "dist/$NAME"
cp "$NODE_BIN" "dist/$NAME/qumbra-node"
cp "$WALLET_BIN" "dist/$NAME/qumbra-wallet"
chmod +x "dist/$NAME/qumbra-node" "dist/$NAME/qumbra-wallet"

# Deliberately NOT stripped: the published binary is built by the same recipe as
# the fleet image's, and diverging here would mean the artifact strangers run is
# not the artifact this project has operational experience with.
cat > "dist/$NAME/PROVENANCE.txt" <<EOF
Qumbra T1 prebuilt binaries
===========================

  release tag   : ${TAG}
  source rev    : ${LAB_REV}          (qumbra-labs/qumbra-lab, private)
  platform      : ${PLATFORM}
  toolchain     : $(rustc -V 2>/dev/null || echo "unknown")
  built by      : the release lane, .github/workflows/release-binaries.yml

Both binaries carry the source revision internally. Ask them, do not trust this file:

  ./qumbra-node halt-status      -> "build rev:" must read ${LAB_REV}
  ./qumbra-wallet --help         -> "build rev:" must read ${LAB_REV}

qumbra-node in this archive is the RESUME build (--features rule-boundary-resume).
Its halt-status says "no halt scheduled" and "resumes past: height 8640". A node
that says ARMED cannot follow the live chain; CI refuses to publish one.

These builds are NOT bit-reproducible and no such claim is made. Provenance here
means the artifact can be tied to a revision (this stamp + SHA256SUMS + the release
notes), not that a third party can rebuild identical bytes.

Verify before running (from the release page):
  sha256sum -c SHA256SUMS          # or: shasum -a 256 -c SHA256SUMS

macOS: these binaries are unsigned and un-notarized. Downloading the tarball with a
browser sets the quarantine attribute and Gatekeeper will refuse to run them; fetch
with curl, or clear it explicitly:
  xattr -d com.apple.quarantine qumbra-node qumbra-wallet

Join instructions: https://github.com/qumbra-labs/qumbra/blob/main/docs/join-and-mine.md
EOF

tar -czf "dist/${NAME}.tar.gz" -C dist "$NAME"
rm -rf "dist/${NAME:?}"

cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256"
else
  shasum -a 256 "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256"
fi
ls -l
cat "${NAME}.tar.gz.sha256"
