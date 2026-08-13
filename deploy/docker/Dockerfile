# syntax=docker/dockerfile:1
#
# Qumbra T0 internal-net node image (M10-T0-3 Phase B-lite, issue #64 amendment 3).
#
# This is the FIRST build of `randomx-rs` (1.4.1) + `qumbra-node` on Linux. The
# deploy/README flags a "RandomX Linux cross-compile caveat" (a macOS-built binary
# will not run on a Linux VPS, and randomx-rs had never been built on Linux in this
# project). Building here validates that caveat and produces a reusable Linux
# artifact for the eventual 4-VPS Phase B-WAN deploy (VPSes are Linux too).
#
# If this build fails at the randomx-rs link/compile step, THAT is a Phase B-lite
# finding (not a task failure): report it, file the Linux-build issue, and fall
# back to the deploy/ 4-local-process mode for the soak (see deploy/docker/README).

# ---- builder ---------------------------------------------------------------
# Pinned to the dev-rig toolchain (rustc 1.95, the rev Cargo.lock was resolved on).
FROM rust:1.95-bookworm AS builder

# randomx-rs builds the RandomX C++ reference library from vendored sources via
# cmake at build time; bindgen (libclang) generates the FFI bindings.
RUN apt-get update && apt-get install -y --no-install-recommends \
        cmake clang libclang-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# The whole workspace: qumbra-node pulls in the qlab-* path-dep crates + Cargo.lock
# (the .dockerignore keeps target/ and .git/ out of the context).
COPY . .

# Build ONLY the node binary in release — the soak needs nothing else, and the
# heavy m4* bench crates are irrelevant here. --locked: honor the pinned lockfile.
#
# NODE_FEATURES selects the emission-boundary variant of the MAIN binary
# (lab #299/#303, docs/i299-emission-boundary-activation.md §3):
#   empty (default)        → ARMED — halts at 8640 (the announcement image)
#   rule-boundary-resume   → the post-boundary release that resumes past 8640
# Two images from one Dockerfile, the main binary being the right variant, so a
# fleet roll is the usual image-digest swap. The drill binaries below are unaffected.
ARG NODE_FEATURES=""
RUN cargo build --release --locked -p qumbra-node ${NODE_FEATURES:+--features "$NODE_FEATURES"} \
    && cp target/release/qumbra-node /usr/local/bin/qumbra-node

# The T1 faucet listener (issue #123). It is a LEAF crate over the same dependency
# graph — plonky3 and randomx-rs are already built for qumbra-node above — so this is
# a cheap incremental build, not a second full one. `entrypoint.sh faucet` runs it
# alongside the four nodes on a KEYLESS node of its own (testnet-plan.md §6.2).
# FAUCET_FEATURES is the faucet's half of the NODE_FEATURES story (issue #397):
# qumbra-faucet embeds a keyless node, and without the resume feature that node
# is ARMED and halts at the emission boundary forever — the public faucet sat at
# 8640 for a day because this build had no features. Pass, for the resume image:
#   --build-arg FAUCET_FEATURES=qumbra-node/rule-boundary-resume
ARG FAUCET_FEATURES=""
RUN cargo build --release --locked -p qumbra-faucet ${FAUCET_FEATURES:+--features "$FAUCET_FEATURES"} \
    && cp target/release/qumbra-faucet /usr/local/bin/qumbra-faucet

# ── halt-height drill binaries (issue #74) ──────────────────────────────────
#
# H1: the halt height is a BINARY RELEASE CONSTANT with no runtime override, so the
# drill needs genuinely different binaries — which is also what a real upgrade is.
# Each of these differs from the one above ONLY in the compile-time `RELEASE` const
# selected by a cargo feature (crates/qumbra-node/src/release.rs).
#
# Cost note: the features gate code inside the leaf crate only, so the heavy
# dependency graph (plonky3, randomx-rs) is built once and each variant is a leaf
# recompile — four cheap rebuilds, not four full builds.
RUN cargo build --release --locked -p qumbra-node --features drill-arm \
    && cp target/release/qumbra-node /usr/local/bin/qumbra-node-armed
RUN cargo build --release --locked -p qumbra-node --features drill-resume \
    && cp target/release/qumbra-node /usr/local/bin/qumbra-node-resume
RUN cargo build --release --locked -p qumbra-node --features drill-resume-norev \
    && cp target/release/qumbra-node /usr/local/bin/qumbra-node-norev
RUN cargo build --release --locked -p qumbra-node --features drill-cancel \
    && cp target/release/qumbra-node /usr/local/bin/qumbra-node-cancel

# ---- runtime ---------------------------------------------------------------
# ---- the explorer's own image (issue #281 / design brief §7 touchpoint 3) ----
#
# `qumbra-explorer` gets its OWN image rather than riding this one, and the reason is
# blast radius, not tidiness: sharing would mean that **editing a page's backend
# produces a new fleet image digest**, so the next roll of the four CONSENSUS hosts
# would carry an explorer change. `MANUAL-DEPLOY.md`'s per-host gate ("one NEW
# finalization after the restart") exists because rolling a signing node is a
# consensus event; coupling a keyless observer's edits to that inverts the risk.
# svc0's keyless roles have no consensus gate at all (`HOST-PULL-SETUP.md`).
#
# Second reason, also not taste: the shared image contains `qumbra-faucet` — the HOT
# KEY binary that the whole svc0/svc1 split exists to keep off the public host
# (`docker-compose.svc-light.yml`: "No key material exists on this host at all …
# that separation is the point"). The keys are not there, so it is not an exploit;
# shipping the spending binary onto the keyless public box still contradicts the
# stated reason for the split.
#
# 🔴 THESE STAGES SIT BEFORE `runtime` ON PURPOSE. This file already warns that a new
# last stage becomes the default target, so "any release build would then have to pass
# --target runtime explicitly, and a forgotten flag fails silently in the direction of
# shipping more, not less." Appending here would mean a `docker build` following
# README.md's own command (which passes no --target) produces an explorer image tagged
# as qumbra-node. Inserting before `runtime` keeps `runtime` last and the documented
# command unchanged.
#
# 🔴 AND THE BUILD IS A SEPARATE STAGE, NOT AN EXTRA `RUN` IN `builder`. Adding the
# explorer's cargo build to `builder` would change `builder`'s layers, which
# `runtime` COPYs from — so the FLEET IMAGE DIGEST WOULD MOVE because a page's
# backend was compiled. `FROM builder AS build-explorer` leaves `builder` and
# `runtime` untouched, so `--target runtime` has a byte-identical input graph.
#
#   docker build -f deploy/docker/Dockerfile --target runtime-explorer \
#     --build-arg GIT_REVISION=$(git rev-parse HEAD) \
#     --build-arg EXPLORER_FEATURES=qumbra-node/rule-boundary-resume \
#     -t ghcr.io/qumbra-labs/qumbra-explorer:<tag> .
# EXPLORER_FEATURES is the explorer's half of the NODE_FEATURES story above, and it
# exists because the two were NOT symmetric and that cost a day of stale public page.
#
# `qumbra-explorer` composes `qumbra-node` (its Cargo.toml) and has no `[features]`
# and no halt code of its own, so it inherits that crate's DEFAULT -- which
# `qumbra-node/Cargo.toml` documents as "arming is the default and resuming is the
# flag". `NODE_FEATURES` reached `-p qumbra-node` only, so every explorer image built
# after lab #325 halted at RULE_BOUNDARY_HEIGHT permanently, with no build-arg able to
# change it. On 2026-08-12 that froze explorer.qumbra.org at 8,640 while the chain ran
# on past it (deploy #127); rolling to a newer explorer tag could not help, because
# every tag was armed.
#
#   empty (default)                        → armed: halts at the boundary
#   qumbra-node/rule-boundary-resume       → resumes past it
#
# The `dep/feature` form is used deliberately: it needs no `[features]` section in
# `qumbra-explorer`, so this adds a build knob without adding a crate-level API.
# Verified: `cargo check -p qumbra-explorer --features
# qumbra-node/rule-boundary-resume` finishes clean with no Cargo.toml change.
#
# 🔴 Threading this is the small fix. Whether an OBSERVER should be halt-aware at all
# is the open question (deploy #127): it participates in nothing and signs nothing,
# and its only job is to keep describing the chain. Arming buys it the honest
# `halting`/`halted` vocabulary during a halt and costs it a freeze afterwards. This
# arg makes the choice expressible; it does not make it.
ARG EXPLORER_FEATURES=""
FROM builder AS build-explorer
ARG EXPLORER_FEATURES
RUN cargo build --release --locked -p qumbra-explorer ${EXPLORER_FEATURES:+--features "$EXPLORER_FEATURES"} \
    && cp target/release/qumbra-explorer /usr/local/bin/qumbra-explorer

FROM debian:bookworm-slim AS runtime-explorer
ARG GIT_REVISION=unknown
LABEL org.opencontainers.image.revision=$GIT_REVISION
LABEL org.opencontainers.image.source=https://github.com/qumbra-labs/qumbra-lab
LABEL org.opencontainers.image.title=qumbra-explorer
LABEL org.opencontainers.image.description="Keyless observer node serving the chain-health projection at /v1/health.json. Deliberately not a transaction explorer, and it serves no HTML."
# Deliberately NOT `iproute2`/`iputils-ping`: those exist in `runtime` for `soak.sh
# netem`'s tc qdisc on the T0 harness, and svc0 runs no drills. Nor `bash`, which is
# there for entrypoint.sh — this image has no entrypoint script. `ca-certificates` is
# kept because a keyless observer that later needs an outbound TLS fetch failing on a
# missing trust store is a bad way to find that out.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build-explorer /usr/local/bin/qumbra-explorer /usr/local/bin/qumbra-explorer

# 🔴 The binary IS the entrypoint, unlike `runtime`. entrypoint.sh's dispatch is
# T0-shaped — `run` demands a node index 0..3 and waits for a shared genesis file
# that svc0 does not have — so a purpose-built image gets the right entrypoint
# instead of an override in someone's compose file. svc0's compose then reads
# `command: ["run", "--config", "/opt/qumbra/explorer.toml"]`, which says what it does.
ENTRYPOINT ["/usr/local/bin/qumbra-explorer"]

FROM debian:bookworm-slim AS runtime
# Provenance (#224 / QUM-72). The key is the one qumbra-deploy's operator check
# already reads (`org.opencontainers.image.revision`). Default is the string
# `unknown`, not empty: an empty label is ambiguous (tooling gap vs forgotten
# flag); `unknown` means nobody passed a revision and is actionable.
# Pass it at build time:
#   --build-arg GIT_REVISION=$(git rev-parse HEAD)
ARG GIT_REVISION=unknown
LABEL org.opencontainers.image.revision=$GIT_REVISION
LABEL org.opencontainers.image.source=https://github.com/qumbra-labs/qumbra-lab
# iproute2 (`tc`) and iputils-ping exist for ONE reason: `soak.sh netem` injects a
# `tc netem` qdisc into each node container so the harness can ask latency questions
# (issue #107 step 1b), and `ping` is how a run proves the qdisc is actually on the
# path rather than merely installed. Neither is used by `qumbra-node`, which never
# reads or configures the network stack; both are inert unless the container is also
# granted NET_ADMIN (docker-compose.yml does; a plain `docker run` does not).
#
# Cost: ~3 MB on an image that is also the artifact pushed to GHCR for the four T0
# hosts, so `tc` lands on those hosts too. If that is unwanted, split a
# `FROM runtime AS runtime-netem` stage and point docker-compose.yml's build at it —
# but note that makes the LAST stage the default target, so any release build would
# then have to pass `--target runtime` explicitly, and a forgotten flag fails silently
# in the direction of shipping more, not less.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/qumbra-node /usr/local/bin/qumbra-node
COPY --from=builder /usr/local/bin/qumbra-faucet /usr/local/bin/qumbra-faucet
COPY --from=builder /usr/local/bin/qumbra-node-armed /usr/local/bin/qumbra-node-armed
COPY --from=builder /usr/local/bin/qumbra-node-resume /usr/local/bin/qumbra-node-resume
COPY --from=builder /usr/local/bin/qumbra-node-norev /usr/local/bin/qumbra-node-norev
COPY --from=builder /usr/local/bin/qumbra-node-cancel /usr/local/bin/qumbra-node-cancel
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# `init` mints the shared genesis + 21 keys once; `run <idx>` starts a node;
# `faucet` starts the T1 faucet on a keyless node (#123).
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
