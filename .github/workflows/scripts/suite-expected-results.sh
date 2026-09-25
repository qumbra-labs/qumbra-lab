#!/usr/bin/env bash
# How many `test result:` lines a COMPLETE `cargo test --workspace` run of this
# tree writes — the denominator the reconciliation step (reconcile-suite.sh)
# compares against. Prints ONE integer on stdout, or exits non-zero with the
# reason on stderr. It never prints a number it is not sure of.
#
# WHY A DERIVATION AND NOT A CHECKED-IN CONSTANT (lab #691, the detector's
# option (b) vs (c)): a constant is a second source of truth that rots — this
# repo had 17 comments pointing at a retired workflow a week after the
# retirement (#692). The manifests ARE what `cargo test` reads, so asking
# `cargo metadata` the same question cargo answers for itself has nothing to
# drift from except cargo's own selection rule, which is spelled out below.
#
# WHY NOT `cargo test --no-run --message-format=json` (the task-book's option
# (c) verbatim): it is a build, it fails on a tree that does not compile — the
# one case where the denominator is MOST needed, because 0 results were
# written — and it does not enumerate doc-tests at all. `cargo metadata
# --no-deps` is a manifest read: no build, no network, well under a second.
#
# THE RULE (cargo's, restated): a plain `cargo test` with no target flags runs
#   * every lib target with `test = true`            (one binary each)
#   * every bin target with `test = true`            (one binary each)
#   * every integration `tests/*.rs` with `test = true` (one binary each)
#   * a doc-test pass for every lib target with `doctest = true` (one
#     `test result:` line each, printed AFTER all the binaries)
# and skips a target whose `required-features` are not all enabled by the
# package's `default` feature set. Benches and examples are not run.
#
# CALIBRATED against three real `suite-log-graviton` artifacts on 2026-08-28:
# it reproduces the first 25 (run 32922325707), the first 75 (33139444620) and
# all 143 = 115 binaries + 28 doc-test sets (33063618205, green) in cargo's
# observed package-name order. If a future green run prints "N of M expected"
# with N != M, THIS FILE's rule is the first suspect, and the detector firing
# on it is the intended behaviour — loud beats silent (lab #402 precedent).
#
# Usage: suite-expected-results.sh [manifest-dir]     (default: cwd)
# Requires: cargo, python3. Both absent ⇒ exit 2 with a named reason.
set -uo pipefail

dir="${1:-.}"

command -v cargo >/dev/null 2>&1 || { echo "suite-expected-results: cargo not on PATH" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "suite-expected-results: python3 not on PATH (needed to read cargo metadata's JSON)" >&2; exit 2; }

# The metadata goes to python through a FILE, never argv: Linux caps a single
# argument at MAX_ARG_STRLEN (128 KiB), and this workspace's `cargo metadata
# --no-deps` JSON is ~126 KB with short local paths — longer on a runner, whose
# absolute paths are repeated per target. Past the cap, exec fails with
# "Argument list too long" and the denominator is lost.
meta=$(mktemp) || { echo "suite-expected-results: mktemp failed" >&2; exit 2; }
trap 'rm -f "$meta"' EXIT
(cd "$dir" && cargo metadata --no-deps --offline --format-version 1 2>/dev/null) >"$meta" \
  || { echo "suite-expected-results: cargo metadata --no-deps failed in $dir" >&2; exit 2; }

python3 - "$meta" <<'PY'
import json, sys

with open(sys.argv[1]) as f:
    m = json.load(f)
members = set(m["workspace_members"])
binaries = 0
doctests = 0
skipped = []

def default_features(pkg):
    feats = pkg.get("features", {})
    enabled, stack = set(), ["default"]
    while stack:
        f = stack.pop()
        if f in enabled or f not in feats:
            continue
        enabled.add(f)
        for dep in feats[f]:
            # "dep:foo" enables an optional dependency, "foo/bar" a dependency's
            # feature — neither is a feature NAME of this package.
            if dep.startswith("dep:") or "/" in dep:
                continue
            stack.append(dep.removesuffix("?"))
    return enabled

for pkg in m["packages"]:
    if pkg["id"] not in members:
        continue
    enabled = default_features(pkg)
    for t in pkg["targets"]:
        kinds = set(t["kind"])
        is_lib = bool(kinds & {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"})
        is_bin = "bin" in kinds
        is_test = "test" in kinds
        if not (is_lib or is_bin or is_test):
            continue  # bench, example, custom-build: not run by `cargo test`
        req = set(t.get("required-features") or [])
        if not req <= enabled:
            skipped.append(f'{pkg["name"]}/{t["name"]} (required-features {sorted(req)})')
            continue
        if t.get("test", True):
            binaries += 1
        if is_lib and t.get("doctest", True):
            doctests += 1

for s in skipped:
    print(f"suite-expected-results: not counted, required-features off by default: {s}", file=sys.stderr)
print(f"suite-expected-results: {binaries} test binaries + {doctests} doc-test sets", file=sys.stderr)
if binaries + doctests <= 0:
    print("suite-expected-results: derived ZERO targets — refusing to print a denominator", file=sys.stderr)
    sys.exit(2)
print(binaries + doctests)
PY
