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

# ---- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/qumbra-node /usr/local/bin/qumbra-node
COPY deploy/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# `init` mints the shared genesis + 21 keys once; `run <idx>` starts a node.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
