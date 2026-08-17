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

SUMS=$(cat release/SHA256SUMS)

cat > release-notes.md <<EOF
Prebuilt \`qumbra-node\` + \`qumbra-wallet\` for the T1 public testnet — no Docker required.

**T1 is a testnet.** Coins have no value and will not survive the next re-genesis.

## Download and verify

Fetch the tarball for your platform and \`SHA256SUMS\`, then:

\`\`\`sh
sha256sum -c SHA256SUMS          # macOS: shasum -a 256 -c SHA256SUMS
tar -xzf qumbra-${TAG}-<platform>.tar.gz
\`\`\`

\`\`\`
${SUMS}
\`\`\`

| platform | what it is |
|---|---|
| \`linux-x86_64-glibc\` | dynamically linked, built against glibc 2.36 (Debian 12) — runs on 2.36 and newer |
| \`linux-aarch64-glibc\` | same, arm64 (this is what the testnet fleet runs) |
| \`macos-arm64\` | Apple Silicon, macOS 11+; **unsigned and un-notarized** — see below |

## Provenance

- Source revision: \`${LAB_REV}\` (\`qumbra-labs/qumbra-lab\`, private during T1).
- Build log, including every assertion below: ${RUN_URL}
- This tag points at \`${TARGET_SHA}\` in *this* (mirror) repository. **The \`t1-\` suffix
  is the short SOURCE revision, from a different repository's history** — do not read the
  tag name as a commit here.
- Both binaries carry the revision internally, so you can ask them rather than trust this page:

\`\`\`sh
./qumbra-node halt-status      # "build rev:" must read ${LAB_REV}
./qumbra-wallet --help         # "build rev:" must read ${LAB_REV}
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
- \`qumbra-node check\` against the genesis published at \`https://seed.qumbra.org/genesis.qmb\`
  exits 0 and verifies it to
  \`138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb\` — the same preflight the
  join guide tells you to run first.

## macOS

The binaries are unsigned and un-notarized. A browser download quarantines them and Gatekeeper
will refuse to run them. Fetch with \`curl\`, or clear the attribute explicitly:

\`\`\`sh
xattr -d com.apple.quarantine qumbra-node qumbra-wallet
\`\`\`

Native macOS mining is supported as of 2026-08-17: above height 8,640 the coinbase rule is exact
integer arithmetic with no libm on the consensus path, and a native arm64 miner was verified live
against the running chain. Windows has no native build (unix-only dependencies); WSL2 runs the
Linux x86_64 binary.

## Next

[How to join and mine](https://github.com/qumbra-labs/qumbra/blob/main/docs/join-and-mine.md)
([中文](https://github.com/qumbra-labs/qumbra/blob/main/docs/join-and-mine-zh.md)) — the binary
path is §2. The container path stays the reproducible baseline and is unchanged.
EOF

echo "----- release-notes.md -----"
cat release-notes.md
