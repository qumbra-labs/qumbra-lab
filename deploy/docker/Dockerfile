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
RUN cargo build --release --locked -p qumbra-node \
    && cp target/release/qumbra-node /usr/local/bin/qumbra-node

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
FROM debian:bookworm-slim AS runtime
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
COPY --from=builder /usr/local/bin/qumbra-node-armed /usr/local/bin/qumbra-node-armed
COPY --from=builder /usr/local/bin/qumbra-node-resume /usr/local/bin/qumbra-node-resume
COPY --from=builder /usr/local/bin/qumbra-node-norev /usr/local/bin/qumbra-node-norev
COPY --from=builder /usr/local/bin/qumbra-node-cancel /usr/local/bin/qumbra-node-cancel
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# `init` mints the shared genesis + 21 keys once; `run <idx>` starts a node.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
