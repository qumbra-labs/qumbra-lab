#!/usr/bin/env bash
# The release notes the public page carries (lab #437, load-bearing requirement 2).
#
# Everything a stranger needs to decide whether to trust the download, and nothing
# they cannot check themselves: the revision, the digests, how to verify them, and
# what the binary will say about itself when asked.
set -euo pipefail

: "${TAG:?TAG is required}"
: "${LAB_REV:?LAB_REV is required}"
: "${TARGET_SHA:?TARGET_SHA is required}"
: "${RUN_URL:?RUN_URL is required}"
: "${NET:?NET (t1 or t2) is required}"
: "${GENESIS_HASH:?GENESIS_HASH is required}"
: "${GENESIS_URL:?GENESIS_URL is required}"

case "$NET" in
  t1) NET_LABEL=T1 ;;
  t2) NET_LABEL=T2 ;;
  *) echo "::error::NET must be t1 or t2, got '$NET'"; exit 1 ;;
esac

SUMS=$(cat release/SHA256SUMS)

cat > release-notes.md <<EOF
Prebuilt \`qumbra-node\` + \`qumbra-wallet\` + \`qumbra-pool\` for the ${NET_LABEL} public testnet — no Docker required.

**${NET_LABEL} is a testnet.** Coins have no value and will not survive the next re-genesis.

## Download and verify

Fetch the archive for your platform and \`SHA256SUMS\`, then:

\`\`\`sh
sha256sum -c SHA256SUMS          # macOS: shasum -a 256 -c SHA256SUMS
tar -xzf qumbra-${TAG}-<platform>.tar.gz
\`\`\`

Windows, in PowerShell — the archive is a \`.zip\` and the digest tool is different:

\`\`\`powershell
Get-FileHash .\\qumbra-${TAG}-windows-x86_64.zip -Algorithm SHA256
# compare that hash against the windows line in SHA256SUMS below, then:
Expand-Archive .\\qumbra-${TAG}-windows-x86_64.zip -DestinationPath .
\`\`\`

\`\`\`
${SUMS}
\`\`\`

| platform | what it is |
|---|---|
| \`linux-x86_64-glibc\` | dynamically linked, built against glibc 2.36 (Debian 12) — runs on 2.36 and newer |
| \`linux-aarch64-glibc\` | same, arm64 (this is what the testnet fleet runs) |
| \`macos-arm64\` | Apple Silicon, macOS 11+; **unsigned and un-notarized** — see below |
| \`windows-x86_64\` | Windows 10/11 x64, \`.zip\`, \`.exe\`; **unsigned** — see below |

## Provenance

- Source revision: \`${LAB_REV}\` (\`qumbra-labs/qumbra-lab\`, private).
- Build log, including every assertion below: ${RUN_URL}
- This tag points at \`${TARGET_SHA}\` in *this* (mirror) repository. **The \`${NET}-\` suffix
  is the short SOURCE revision, from a different repository's history** — do not read the
  tag name as a commit here.
- Node and wallet carry the revision internally, so you can ask them rather than trust this page:

\`\`\`sh
./qumbra-node halt-status      # "build rev:" must read ${LAB_REV}
./qumbra-wallet --help         # "build rev:" must read ${LAB_REV}
./qumbra-pool --help           # identifies itself (no build-rev stamp)
\`\`\`

**These builds are not bit-reproducible**, and no such claim is made. Provenance here means
an artifact can be tied to a revision; it does not mean you can rebuild identical bytes.

## What CI proved before this page existed

Per artifact, on the platform it was built for:

- \`qumbra-node halt-status\` reports \`no halt scheduled\` and \`resumes past: height 8640\`.
  A node built without \`--features rule-boundary-resume\` is **ARMED** — it stops at height
  8,640 and cannot follow the chain. An ARMED artifact fails the release job outright.
- The frozen consensus digest, both as declared and as recomputed from the binary's own
  compiled-in constants, equals the testnet's.
- \`qumbra-node check\` against the genesis published at \`${GENESIS_URL}\`
  exits 0 and verifies it to
  \`${GENESIS_HASH}\` — the same preflight the
  join guide tells you to run first. A T2 cut is refused in preflight if that
  URL still serves the T1 genesis.

## macOS

The binaries are unsigned and un-notarized. A browser download quarantines them and Gatekeeper
will refuse to run them. Fetch with \`curl\`, or clear the attribute explicitly:

\`\`\`sh
xattr -d com.apple.quarantine qumbra-node qumbra-wallet qumbra-pool
\`\`\`

Native macOS mining is supported as of 2026-08-17: above height 8,640 the coinbase rule is exact
integer arithmetic with no libm on the consensus path, and a native arm64 miner was verified live
against the running chain.

## Windows

**The executables are unsigned.** There is no code-signing certificate on this project and none
is implied. The first run of either one shows SmartScreen's "Windows protected your PC" — the
way through is **More info → Run anyway**. Microsoft Defender may also flag a CPU miner on
reputation alone. Verify the zip's SHA-256 against the list above *before* you do either.

Run \`qumbra-node.exe\` from a PowerShell or Windows Terminal window you opened yourself, not by
double-clicking. It is a long-running console process, and **Ctrl-C is the stop that reliably
flushes its snapshot**; closing the console window also flushes, but Windows caps that at about
five seconds and a busy miner can miss it. Nothing is lost either way — the block log is the
source of truth and a node with a stale snapshot replays to the same state — but a missed flush
costs replay time on the next start.

One config trap, and it is the first one everybody hits: \`node.toml\` is TOML, and a
double-quoted TOML string treats \`\\\` as an escape. Write Windows paths in **single quotes**
(\`data_dir = 'C:\\Users\\you\\qumbra-data'\`) or with forward slashes.

WSL2 remains supported and unchanged: inside it, use the \`linux-x86_64-glibc\` tarball.

## Next

[How to join and mine](https://github.com/qumbra-labs/qumbra/blob/main/docs/join-and-mine.md)
([中文](https://github.com/qumbra-labs/qumbra/blob/main/docs/join-and-mine-zh.md)) — the binary
path is §2. The container path stays the reproducible baseline and is unchanged.
EOF

echo "----- release-notes.md -----"
cat release-notes.md
