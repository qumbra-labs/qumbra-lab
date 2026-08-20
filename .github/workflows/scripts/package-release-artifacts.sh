#!/usr/bin/env bash
# Packaging for the release lane (lab #437, pool added by lab #516). One archive
# per platform, holding the three binaries a joiner needs (node, wallet, pool)
# and a PROVENANCE.txt that keeps the archive self-describing after it has been
# copied off the release page.
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
: "${NET:?NET (t1 or t2) is required}"

# ── platform shape (lab #478) ────────────────────────────────────────────────
# ONE input decides three things that must never disagree: the executable
# suffix, the archive format, and which OS-specific "your OS will refuse to run
# this unsigned binary" paragraph goes in PROVENANCE.txt. Deriving all three
# from $PLATFORM is what stops a windows leg from shipping `.tar.gz` of
# extensionless files, which would download and then do nothing.
case "$PLATFORM" in
  windows-*) EXE=".exe"; ARCHIVE="zip" ;;
  *)         EXE="";     ARCHIVE="tar.gz" ;;
esac

NODE_BIN="${NODE_BIN:-target/release/qumbra-node${EXE}}"
WALLET_BIN="${WALLET_BIN:-target/release/qumbra-wallet${EXE}}"
POOL_BIN="${POOL_BIN:-target/release/qumbra-pool${EXE}}"

case "$NET" in
  t1) NET_LABEL=T1 ;;
  t2) NET_LABEL=T2 ;;
  *) echo "::error::NET must be t1 or t2, got '$NET'"; exit 1 ;;
esac

NAME="qumbra-${TAG}-${PLATFORM}"
rm -rf dist; mkdir -p "dist/$NAME"
cp "$NODE_BIN" "dist/$NAME/qumbra-node${EXE}"
cp "$WALLET_BIN" "dist/$NAME/qumbra-wallet${EXE}"
cp "$POOL_BIN" "dist/$NAME/qumbra-pool${EXE}"
chmod +x "dist/$NAME/qumbra-node${EXE}" "dist/$NAME/qumbra-wallet${EXE}" "dist/$NAME/qumbra-pool${EXE}"

# The "your OS will refuse to run this" paragraph, built BEFORE the heredoc that
# uses it. It is a variable and not a `$(case …)` inside PROVENANCE.txt because a
# heredoc nested inside a command substitution inside a heredoc does not parse in
# bash — caught by running this script, not by reading it.
case "$PLATFORM" in
  windows-*)
    IFS= read -r -d '' UNSIGNED_NOTE <<'WIN' || true

Windows: these executables are unsigned. There is no code-signing certificate on
this project and none is implied (lab #478 put signing explicitly out of scope).
SmartScreen will show "Windows protected your PC" the first time you run either
one; the path through it is "More info" -> "Run anyway". Microsoft Defender may
also flag a CPU miner on reputation alone. Do not take this file's word for what
you downloaded — check the zip against SHA256SUMS in PowerShell:

  Get-FileHash .\qumbra-<tag>-windows-x86_64.zip -Algorithm SHA256

Run both binaries from a terminal you opened yourself (PowerShell or Windows
Terminal), not by double-clicking: qumbra-node is a long-running console process
and Ctrl-C is the stop that reliably flushes its snapshot. Closing the console
window also flushes, but Windows caps that at about five seconds.
WIN
    ;;
  *)
    IFS= read -r -d '' UNSIGNED_NOTE <<'NIX' || true

macOS: these binaries are unsigned and un-notarized. Downloading the tarball with a
browser sets the quarantine attribute and Gatekeeper will refuse to run them; fetch
with curl, or clear it explicitly:
  xattr -d com.apple.quarantine qumbra-node qumbra-wallet qumbra-pool
NIX
    ;;
esac

# Deliberately NOT stripped: the published binary is built by the same recipe as
# the fleet image's, and diverging here would mean the artifact strangers run is
# not the artifact this project has operational experience with.
cat > "dist/$NAME/PROVENANCE.txt" <<EOF
Qumbra ${NET_LABEL} prebuilt binaries
===========================

  release tag   : ${TAG}
  net           : ${NET_LABEL}
  source rev    : ${LAB_REV}          (qumbra-labs/qumbra-lab, private)
  platform      : ${PLATFORM}
  toolchain     : $(rustc -V 2>/dev/null || echo "unknown")
  built by      : the release lane, .github/workflows/release-binaries.yml

Node and wallet carry the source revision internally. Ask them, do not trust this file:

  ./qumbra-node halt-status      -> "build rev:" must read ${LAB_REV}
  ./qumbra-wallet --help         -> "build rev:" must read ${LAB_REV}
  ./qumbra-pool --help           -> identifies itself; no build-rev stamp (lab #516)

qumbra-node in this archive is the RESUME build (--features rule-boundary-resume).
Its halt-status says "no halt scheduled" and "resumes past: height 8640". A node
that says ARMED cannot follow the live chain; CI refuses to publish one.
qumbra-pool is the T2 pool listener (RandomX, same constraint as the node).

These builds are NOT bit-reproducible and no such claim is made. Provenance here
means the artifact can be tied to a revision (this stamp + SHA256SUMS + the release
notes), not that a third party can rebuild identical bytes.

Verify before running (from the release page):
  sha256sum -c SHA256SUMS          # or: shasum -a 256 -c SHA256SUMS
${UNSIGNED_NOTE}

Join instructions: https://github.com/qumbra-labs/qumbra/blob/main/docs/join-and-mine.md
EOF

# zip on Windows, tar.gz everywhere else. A `.tar.gz` is a second tool a Windows
# user has to find before they can even see the binaries; Explorer opens a `.zip`.
# PowerShell's Compress-Archive is used rather than `7z` because `pwsh` is the one
# archiver guaranteed present on `windows-latest`.
case "$ARCHIVE" in
  tar.gz)
    tar -czf "dist/${NAME}.tar.gz" -C dist "$NAME"
    ;;
  zip)
    pwsh -NoProfile -NonInteractive -Command \
      "Compress-Archive -Path 'dist/${NAME}' -DestinationPath 'dist/${NAME}.zip' -CompressionLevel Optimal"
    ;;
  *) echo "::error::unknown ARCHIVE '$ARCHIVE'"; exit 1 ;;
esac
ARTIFACT="${NAME}.${ARCHIVE}"
[ -f "dist/$ARTIFACT" ] || { echo "::error::packaging produced no dist/$ARTIFACT"; exit 1; }

# READ THE ARCHIVE BACK (lab #478). Not paranoia: `tar -C dist NAME` and
# `Compress-Archive -Path dist/NAME` are two different tools' opinions about
# whether the top-level folder is inside the archive, and getting that wrong
# ships an archive that extracts into the wrong shape — which nothing downstream
# checks, because SHA256SUMS is happy to certify a correctly-transferred wrong
# layout. So list the entries and require the three files at the path the join
# doc tells a stranger to `cd` into.
case "$ARCHIVE" in
  tar.gz) ENTRIES=$(tar -tzf "dist/$ARTIFACT") ;;
  zip)    ENTRIES=$(pwsh -NoProfile -NonInteractive -Command \
            "Add-Type -A System.IO.Compression.FileSystem; \
             [IO.Compression.ZipFile]::OpenRead((Resolve-Path 'dist/$ARTIFACT')).Entries \
             | ForEach-Object { \$_.FullName }") ;;
esac
echo "--- archive entries ---"; echo "$ENTRIES"
for want in "qumbra-node${EXE}" "qumbra-wallet${EXE}" "qumbra-pool${EXE}" "PROVENANCE.txt"; do
  echo "$ENTRIES" | tr '\\' '/' | grep -qF "${NAME}/${want}" \
    || { echo "::error::${ARTIFACT} does not contain ${NAME}/${want} — the archive's layout is not the one the join doc documents"; exit 1; }
done

rm -rf "dist/${NAME:?}"

cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$ARTIFACT" > "${ARTIFACT}.sha256"
else
  shasum -a 256 "$ARTIFACT" > "${ARTIFACT}.sha256"
fi
ls -l
cat "${ARTIFACT}.sha256"
