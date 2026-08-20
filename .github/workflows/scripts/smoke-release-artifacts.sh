#!/usr/bin/env bash
# Per-platform smoke for the release lane (lab #437, load-bearing requirement 3):
# **the preflight a real user runs first**, run against the real published inputs.
#
# `qumbra-node check` exercises the same byte/format/hash gate as startup without
# binding a socket (docs/join-and-mine.md §2), so it is safe on a CI runner and it
# is the exact command the join doc tells a stranger to run before `run`.
#
# WHY THE LIVE GENESIS AND NOT A LOCALLY MINTED ONE: a smoke against a genesis this
# job created would prove the binary agrees with itself. What needs proving is that
# the binary agrees with the file every joiner will actually download — including
# that the file is still being served, and still hashes to the pin the join doc and
# the announcement publish. If seed.qumbra.org is down, this job fails; that is a
# true statement about a stranger's path today, not a false negative about the
# binary. The error message below says which of the two happened.
#
# ORDERING CONSTRAINT (lab #516): this smoke verifies the PUBLISHED genesis, so a
# T2 release can only be cut AFTER cutover has repointed the seed host. The
# preflight job refuses earlier, by name, if the published file is still T1
# ('published genesis is still t1 — run this after the cutover'). Do not weaken
# that into a skip: a green T2 cut against a T1 genesis would publish binaries
# that cannot join the net the announcement describes.
set -euo pipefail

: "${NODE_BIN:?NODE_BIN (path to the built qumbra-node) is required}"
: "${GENESIS_URL:?GENESIS_URL is required}"
: "${GENESIS_HASH:?GENESIS_HASH is required}"
: "${DIAL_PEERS:?DIAL_PEERS (a TOML array literal) is required}"

fail() { echo "::error::$*"; exit 1; }

# Two spellings of the same directory, and lab #478 is why they are two.
#
# `$WORK` is what THIS SCRIPT uses — a POSIX path, because everything below is
# bash. `$WORK_NATIVE` is what goes INTO THE TOML, i.e. what `qumbra-node` will
# hand to `std::fs`. On Linux and macOS they are the same string. On a Windows
# runner they are not: bash reports `/d/a/qumbra-lab/...`, which a Windows binary
# reads as a path on the *current drive* named `\d\a\...`, so the node would
# create its datadir somewhere nobody looks and the smoke would pass while
# testing the wrong thing. `cygpath -w` is the conversion, and it exists on the
# runner precisely because Git for Windows is what provides bash there.
WORK="$(pwd)/.release-smoke"
rm -rf "$WORK"; mkdir -p "$WORK"
if command -v cygpath >/dev/null 2>&1; then
  WORK_NATIVE="$(cygpath -w "$WORK")"
  PATHSEP='\'
else
  WORK_NATIVE="$WORK"
  PATHSEP='/'
fi
echo "smoke workdir: $WORK  (as the node will see it: $WORK_NATIVE)"

if ! curl -fsSL --retry 5 --retry-delay 5 --max-time 120 "$GENESIS_URL" -o "$WORK/genesis.qmb"; then
  fail "could not download $GENESIS_URL. This is an availability failure of the PUBLISHED genesis, not a verdict on the binary — but it is also exactly what a stranger following the join doc would hit right now."
fi
ls -l "$WORK/genesis.qmb"

# The minimal joiner config from docs/join-and-mine.md §2 — verify-only, no
# committee keys, mining off. A public joiner holds no signing keys, and a smoke
# that named one would be testing an operator's config rather than a stranger's.
#
# The two path values are TOML **literal** strings (single quotes) since lab
# #478. A Windows path is full of backslashes and a TOML *basic* string treats
# `\` as an escape introducer, so `data_dir = "C:\qumbra\data"` is either a parse
# error or a different path — the first trap a Windows joiner hits, and the join
# doc now says so. Literal strings take the bytes as written and are identical
# TOML on every platform, so the Linux and macOS legs are unaffected.
cat > "$WORK/node.toml" <<EOF
data_dir = '${WORK_NATIVE}${PATHSEP}data'
listen_addr = "0.0.0.0:9400"
dial_peers = $DIAL_PEERS
genesis_file = '${WORK_NATIVE}${PATHSEP}genesis.qmb'
expected_genesis_hash = "$GENESIS_HASH"
mining = false
EOF
cat "$WORK/node.toml"

echo "===== qumbra-node check ====="
"$NODE_BIN" check --config "$WORK/node.toml" | tee "$WORK/check.txt"
echo "============================="

grep -qF "genesis hash: $GENESIS_HASH" "$WORK/check.txt" \
  || fail "the served genesis did not verify to the pinned hash $GENESIS_HASH. Either the published file changed or the binary's genesis format did — both are stop-and-look, not retry."
# `check` prints the halt plan too, so the resume-variant claim is made twice by
# two different code paths in the same job (halt-status is the other).
grep -qF "halt plan:    no halt scheduled" "$WORK/check.txt" \
  || fail "check reports a halt plan other than 'no halt scheduled' — this is an ARMED artifact."

rm -rf "$WORK"
echo "smoke: OK — this binary preflights clean against the published genesis"
