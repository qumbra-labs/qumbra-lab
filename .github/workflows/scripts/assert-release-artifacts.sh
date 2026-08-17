#!/usr/bin/env bash
# THE GATE of the release lane (lab #437, load-bearing requirement 1).
#
# Interrogates the two binaries that are about to be packaged and refuses every
# way they can be wrong-but-plausible:
#
#   - an ARMED node (a bare `cargo build`) — it halts at the boundary and cannot
#     follow today's chain. #397 is the record of what one deployed armed binary
#     costs: the public faucet froze at 8,640 for ~24 h.
#   - a node whose frozen constants are not the fleet's consensus constants,
#     declared OR recomputed (node-image.yml's check, ported to a bare binary).
#   - a binary that ignored `QUMBRA_BUILD_REV`, i.e. an artifact that cannot be
#     tied back to the revision the release notes will claim.
#
# WHY THIS IS A FILE AND NOT INLINE YAML, against this repo's usual habit: it runs
# on THREE platforms (two Linux legs in a container, one macOS leg native) and the
# assertions must be identical on all three. Inlining it would be three copies that
# drift — and this project has already paid for exactly that shape once, between
# explorer-image.yml and node-image.yml (lab #428: one file's readback grep was
# wrong in a way the other file's was not). It is also why the offline test at
# .github/workflows/tests/release-assertions/ can exercise it at all: a script that
# reads `$NODE_BIN halt-status` can be pointed at a captured fixture, and a step
# buried in YAML on a paid runner cannot.
#
# 🔴 IF A THIRD BINARY EVER JOINS THE TARBALL, IT NEEDS ITS OWN CHECK HERE. This
# gate interrogates `qumbra-node` for the resume variant and both binaries for the
# build stamp — nothing more. #397 is precisely the shape of what gets missed: a
# crate that COMPOSES qumbra-node (the faucet, the explorer) inherits its default,
# which is ARMED, and no build arg aimed at `-p qumbra-node` reaches it. Adding
# qumbra-explorer or qumbra-faucet to a release tarball without adding an assertion
# for it would ship that same silent arming to strangers.
#
# Inputs, all required — no defaults, deliberately. A default pin is a pin nobody
# notices going stale.
set -euo pipefail

: "${NODE_BIN:?NODE_BIN (path to the built qumbra-node) is required}"
: "${WALLET_BIN:?WALLET_BIN (path to the built qumbra-wallet) is required}"
: "${EXPECTED_BUILD_REV:?EXPECTED_BUILD_REV (the lab commit being released) is required}"
: "${FROZEN_PIN:?FROZEN_PIN is required}"
: "${EXPECTED_REVISION:?EXPECTED_REVISION is required}"
: "${EXPECTED_DOMAIN:?EXPECTED_DOMAIN is required}"
: "${RULE_BOUNDARY_HEIGHT:?RULE_BOUNDARY_HEIGHT is required}"

fail() { echo "::error::$*"; exit 1; }

echo "===== qumbra-node halt-status ====="
# `halt-status` exits non-zero when the release refuses to start, and pipefail
# carries that through `tee` — a refusing binary must never reach the packaging
# step regardless of what the greps below say.
"$NODE_BIN" halt-status | tee halt.txt
echo "==================================="

# ---------------------------------------------------------------------------
# 1. It must be the RESUME build. Three independent readings of the same fact,
#    because each one alone has a plausible failure: the plan line could be
#    reworded, the `resumes past` line is absent from an armed binary rather
#    than wrong, and a bare `ARMED` grep would survive a future third variant.
# ---------------------------------------------------------------------------
grep -qFx "  halt plan:    no halt scheduled" halt.txt \
  || fail "this artifact is NOT the resume build — its halt plan is not 'no halt scheduled'. A bare \`cargo build -p qumbra-node\` is ARMED and halts at ${RULE_BOUNDARY_HEIGHT}; the release build needs --features rule-boundary-resume."
grep -qFx "  resumes past: height ${RULE_BOUNDARY_HEIGHT} (post-halt rules apply above it)" halt.txt \
  || fail "this artifact does not declare that it resumes past height ${RULE_BOUNDARY_HEIGHT} — it cannot follow the live chain."
# 2026-08-17: "ARMED" is no longer unambiguous — the name-service banner (PR #436)
# legitimately prints "name service: ARMED … above height 19008" and that line is
# REQUIRED in a post-#367 release (an inert binary forks silently at 19,009). So the
# poison check anchors on the halt-plan line specifically, and the name line flips
# from forbidden to asserted-present. First caught live: run 32011357820, where the
# blunt grep rejected the exact release the name boundary needs.
if grep -E "^  halt plan:" halt.txt | grep -q "ARMED"; then
  fail "the halt-plan line says ARMED. An emission-armed binary published as a release hands every stranger a node that stops at ${RULE_BOUNDARY_HEIGHT} (issue #397)."
fi

# The name boundary must be ARMED in this and every later release (lab #367; the
# no-halt crossing means an un-armed binary walks onto a dead fork at 19,009).
grep -q "name service: ARMED" halt.txt \
  || fail "this artifact's name service is NOT armed — it forks silently at the name boundary (lab #367). Build from a post-135078c tree."

# ---------------------------------------------------------------------------
# 2. It must carry the fleet's consensus constants. Verbatim from
#    node-image.yml's frozen-digest gate, and pinned for the same reason: a
#    consensus binary's "did it really build what I think" question is "are its
#    constants the consensus constants". A legitimate re-genesis WILL fail here
#    until the pins in release-binaries.yml are updated — that is the point.
# ---------------------------------------------------------------------------
DECLARED=$(sed -n 's/^  frozen digest: //p' halt.txt | sed -n 1p)
RECOMPUTED=$(sed -n '/recomputed from THIS/{n;p;}' halt.txt | tr -d ' ')
REVISION=$(sed -n 's/^  revision:[[:space:]]*//p' halt.txt | sed -n 1p)
DOMAIN=$(sed -n 's/^  rule domain:[[:space:]]*//p' halt.txt | sed -n 1p)

[ "$DECLARED" = "$FROZEN_PIN" ] \
  || fail "FROZEN DIGEST DRIFT — the revision declares '$DECLARED', the fleet runs $FROZEN_PIN. A consensus constant moved; this binary must not be published."
[ "$RECOMPUTED" = "$FROZEN_PIN" ] \
  || fail "FROZEN DIGEST DRIFT — recomputed-from-constants is '$RECOMPUTED', declared/pinned is $FROZEN_PIN. The binary's compiled-in constants disagree with the revision it carries."
[ "$REVISION" = "$EXPECTED_REVISION" ] \
  || fail "revision mismatch — got '$REVISION', want $EXPECTED_REVISION."
[ "$DOMAIN" = "$EXPECTED_DOMAIN" ] \
  || fail "rule-domain mismatch — got '$DOMAIN', want $EXPECTED_DOMAIN. The PoW domain above the boundary is what keeps a pre-rule miner's branch invalid; a wrong one forks."
grep -qE '^  validate: +OK' halt.txt \
  || fail "halt-status did not report 'validate: OK' — this release refuses to start."

# ---------------------------------------------------------------------------
# 3. Provenance. The tarball has no OCI label, so the stamp inside the binary is
#    the only thing tying the download to a revision. Grep the value BACK OUT
#    rather than trusting that the env var was honoured: a build that ignored
#    QUMBRA_BUILD_REV prints the `unstamped` sentence and must not ship as
#    though it were stamped.
# ---------------------------------------------------------------------------
NODE_REV=$(sed -n 's/^  build rev:[[:space:]]*//p' halt.txt | sed -n 1p)
[ "$NODE_REV" = "$EXPECTED_BUILD_REV" ] \
  || fail "qumbra-node build stamp is '$NODE_REV', expected $EXPECTED_BUILD_REV. Either QUMBRA_BUILD_REV did not reach the build, or this is not the binary that was just built."

echo "===== qumbra-wallet --help (header) ====="
# The wallet prints its stamp on the first line of --help; --help exits 0.
"$WALLET_BIN" --help 2>&1 | sed -n '1,3p' | tee wallet-help.txt
echo "========================================"
WALLET_REV=$(sed -n 's/^build rev: //p' wallet-help.txt | sed -n 1p)
[ "$WALLET_REV" = "$EXPECTED_BUILD_REV" ] \
  || fail "qumbra-wallet build stamp is '$WALLET_REV', expected $EXPECTED_BUILD_REV. The two binaries in one tarball must be from one revision — a wallet from a different build is precisely the confusion the stamp exists to prevent."

echo "artifact assertions: OK (resume build, frozen digest pinned, both binaries stamped $EXPECTED_BUILD_REV)"
