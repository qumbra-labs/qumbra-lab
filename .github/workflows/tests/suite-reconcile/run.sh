#!/usr/bin/env bash
# Offline validation for the acceptance suite's reconciliation
# (../../scripts/reconcile-suite.sh and ../../scripts/suite-expected-results.sh,
# used by ../../acceptance-graviton.yml).
#
# WHY THIS EXISTS (lab #691). The step under test runs once per acceptance, on a
# Graviton rig, after a ~50-minute suite, and its interesting branch — "this run
# was CUT OFF, the counts below are partial" — fires only when that suite is
# killed by a timeout, an OOM or an eviction. Nobody rehearses that on purpose,
# so before this file the branch had never executed anywhere; the defect #691
# fixes is precisely a reconciliation that printed a one-third run in the same
# table as a complete one. "I believe it would fire" is not evidence; this is.
#
# The fixtures are REAL `suite-log-graviton` artifacts, byte-for-byte (ANSI
# escapes included — the `Running` lines are `\e[1m\e[92m     Running\e[0m …`,
# which is why a naive grep on `Running (unittests|tests/)` counted zero):
#
#   suite-32922325707-0e6d58b-failfast.log   2026-08-26, red. The fail-fast era:
#       cargo stopped after binary 25 of 115 (`qlab_node` lib failed), 25
#       `test result:` lines, passed=836 failed=1 ignored=3. THE defect run.
#   suite-33063618205-2b41e901-green.log     2026-08-27, green. Complete: 115
#       `Running` + 28 `Doc-tests` = 143 `test result:` lines, 2411/0/15.
#
# The cut-mid-binary case is derived from the green log at test time (head to a
# line between a `Running` and its `test result:`) rather than checked in as a
# third 200 KB file; the derivation is one `head -n` and is printed on failure.
#
# Wired into prefilter.yml's shell-suites job. Requires: bash, sed, awk, grep,
# python3 (the derivation case also needs cargo — `cargo metadata`, no build).
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixtures"
RECON="$HERE/../../scripts/reconcile-suite.sh"
EXPECT="$HERE/../../scripts/suite-expected-results.sh"
GREEN="$FIX/suite-33063618205-2b41e901-green.log"
FAILFAST="$FIX/suite-32922325707-0e6d58b-failfast.log"

PASS=0
FAIL=0
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# run_recon <name> <log|-> <exit-code|none> <expected|derive>
#   Runs the script with the summary captured to $TMP/<name>.summary and stdout
#   to $TMP/<name>.out. GITHUB_SHA is fixed so headings are deterministic.
run_recon() {
  local name=$1 log=$2 code=$3 expected=$4
  local exitfile="$TMP/$name.exit"
  [ "$code" = none ] || echo "$code" > "$exitfile"
  local -a env=(GITHUB_SHA=0123456789abcdef GITHUB_STEP_SUMMARY="$TMP/$name.summary" SUITE_LANE=test-lane)
  [ "$expected" = derive ] || env+=(SUITE_EXPECTED_RESULTS="$expected")
  : > "$TMP/$name.summary"
  env "${env[@]}" bash "$RECON" "$log" "$exitfile" > "$TMP/$name.out" 2>&1
  echo $? > "$TMP/$name.rc"
}

# expect <name> <what> <file: summary|out|rc> <grep -E pattern>
expect() {
  local name=$1 what=$2 file=$3 pat=$4
  if grep -qE -- "$pat" "$TMP/$name.$file"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL [$name] $what"
    echo "      wanted /$pat/ in $file; got:"
    sed 's/^/      | /' "$TMP/$name.$file" | head -40
  fi
}
# refute <name> <what> <file> <pattern> — the pattern must NOT appear
refute() {
  local name=$1 what=$2 file=$3 pat=$4
  if grep -qE -- "$pat" "$TMP/$name.$file"; then
    FAIL=$((FAIL + 1))
    echo "FAIL [$name] $what"
    echo "      did not want /$pat/ in $file; got:"
    grep -nE -- "$pat" "$TMP/$name.$file" | sed 's/^/      | /' | head -10
  else
    PASS=$((PASS + 1))
  fi
}

# ── 1. A complete green run: cargo returned 0, 143 of 143 — says so, no red. ──
run_recon green "$GREEN" 0 143
expect green "exits 0"                          rc      '^0$'
expect green "counts the real totals"           out     '^passed=2411 failed=0 ignored=15$'
expect green "reports 143 of 143"               summary '\*\*143 of 143 expected\*\*'
expect green "cargo returned, exit 0"           summary '\| cargo returned \| yes, exit 0 \|'
expect green "verdict complete"                 out     '^verdict=complete cargo_returned=1 cargo_exit=0 results=143 of 143 expected running=143$'
expect green "green check mark"                 summary '^✅ Complete and green: cargo returned 0'
refute green "no red line on a complete run"    summary '🔴'
refute green "no error annotation"              out     '^::error::'
expect green "per-binary table attributes doc-tests too" summary '^\| `Doc-tests qumbra_wallet` \| [0-9]+ \| 0 \| [0-9]+ \|$'
expect green "the command it prints carries --no-fail-fast" summary '`cargo test --release --workspace --locked --no-fail-fast -- --test-threads=1`'
expect green "peak memory line survives the escape strip"  summary 'Maximum resident set size \(kbytes\): 16371712'

# ── 1b. Complete but RED: 143 of 143 present, cargo exited 101. ───────────────
# What the deliberate red-path run under --no-fail-fast looks like: complete,
# so the table's failures are all of them — the summary has to say exactly that
# and must not print the green check.
run_recon completered "$GREEN" 101 143
expect completered "exits 0"                     rc      '^0$'
expect completered "orange, not green"           summary '^🟠 Complete but RED: cargo exited 101, and every expected test result set is present'
expect completered "says these are all the failures" summary 'the failures below are ALL of them, not the first one'
refute completered "no green check on a red run" summary '✅'
refute completered "no red truncation line"      summary '🔴'

# ── 2. THE DEFECT RUN, as the new step would see a cut-off: no suite.exit. ─────
# 25 of 143, cargo never returned. Must say TRUNCATED, must still exit 0, and
# must still print the partial counts (they are true; they are just not the
# whole story).
run_recon cutoff "$FAILFAST" none 143
expect cutoff "exits 0 — never a gate"           rc      '^0$'
expect cutoff "says TRUNCATED"                   summary '^🔴 \*\*TRUNCATED — this is not a zero-failure run\.'
expect cutoff "says 25 of 143"                   summary '25 of 143 expected test result sets were written; 118 never reported'
expect cutoff "cargo did not return"             summary '\| cargo returned \| \*\*NO\*\* — no `suite\.exit`; the step was cut off \|'
expect cutoff "annotates the run"                out     '^::error::TRUNCATED'
expect cutoff "still prints the partial counts"  out     '^passed=836 failed=1 ignored=3$'
expect cutoff "verdict truncated"                out     '^verdict=truncated cargo_returned=0 cargo_exit=none results=25 of 143 expected running=25$'
refute cutoff "does not claim completeness"      summary '✅'

# ── 3. The same log with suite.exit=101: cargo RETURNED but 25 != 143. ────────
# This is what the fail-fast era would have printed under the new step — and
# what a build-then-selection drift would print today. Must be loud, distinct
# from TRUNCATED (the reader's next move is different), still exit 0.
run_recon incomplete "$FAILFAST" 101 143
expect incomplete "exits 0"                      rc      '^0$'
expect incomplete "says INCOMPLETE, names exit"  summary '^🔴 \*\*INCOMPLETE — this is not a zero-failure run\. cargo returned \(exit 101\) but wrote only 25 of 143 expected test result sets; 118 never reported\.'
expect incomplete "annotates"                    out     '^::error::INCOMPLETE'
refute incomplete "not TRUNCATED"                summary 'TRUNCATED'

# ── 4. Cut MID-BINARY: a `Running` line with no `test result:` after it. ──────
# Derived from the green log: keep everything up to and including the 60th
# `Running` line plus a few of its tests, drop the rest. 59 results, 60 starts.
cut_line=$(grep -nE $'^\e\\[1m\e\\[92m +Running\e\\[0m ' "$GREEN" | sed -n '60p' | cut -d: -f1)
[ -n "$cut_line" ] || { echo "FAIL [midbinary] could not locate the 60th Running line in $GREEN"; FAIL=$((FAIL + 1)); cut_line=1; }
head -n "$((cut_line + 3))" "$GREEN" > "$TMP/midbinary.log"
sixtieth=$(sed -n "${cut_line}p" "$GREEN" | sed $'s/\x1b\\[[0-9;]*m//g; s/^ *//; s/ (.*//')
run_recon midbinary "$TMP/midbinary.log" none 143
expect midbinary "exits 0"                       rc      '^0$'
expect midbinary "59 results counted"            out     'results=59 of 143 expected running=60'
expect midbinary "names the binary it stopped in" summary "\| started, never reported \| \`$sixtieth\` \|"
expect midbinary "TRUNCATED says where"          summary "It stopped inside \`$sixtieth\`"
expect midbinary "annotates"                     out     '^::error::TRUNCATED'

# ── 5. cargo returned but wrote NOTHING: the tree did not build. ──────────────
: > "$TMP/empty.log"
run_recon nobuild "$TMP/empty.log" 101 143
expect nobuild "exits 0"                         rc      '^0$'
expect nobuild "says NO TEST RESULTS"            summary '^🔴 \*\*NO TEST RESULTS — this is not a zero-failure run\. cargo returned \(exit 101\) without running a single test binary: the tree did not build\. 143 result sets were expected\.'
expect nobuild "zeros, not blanks"               out     '^passed=0 failed=0 ignored=0$'

# ── 6. Denominator stale in the OTHER direction: 143 written, 140 expected. ───
# The counts are complete; the rule is wrong. Must not be silent about that.
run_recon overcount "$GREEN" 0 140
expect overcount "exits 0"                       rc      '^0$'
expect overcount "says the denominator is stale" summary '^🔴 \*\*MORE RESULTS THAN EXPECTED \(143 of 140 expected\)\.'
expect overcount "names the file to fix"         summary 'suite-expected-results\.sh is stale'

# ── 7. No suite.log at all: the pre-#691 sentence, unchanged. ─────────────────
run_recon nolog "$TMP/does-not-exist.log" none 143
expect nolog "exits 0"                           rc      '^0$'
expect nolog "the original sentence"             summary '^🔴 \*\*No `suite\.log`\.\*\* The suite step did not get far enough to write one, so there is nothing to reconcile — this is not a zero-failure run\.'
expect nolog "annotates"                         out     '^::error::suite\.log absent'

# ── 8. Denominator could not be derived: loud, not silent, counts still shown. ─
# Point the derivation at a directory with no manifest by running from $TMP with
# no override; suite-expected-results.sh fails and the reconciliation must say so.
echo 0 > "$TMP/noderive.exit"
( cd "$TMP" && GITHUB_SHA=0123456789abcdef GITHUB_STEP_SUMMARY="$TMP/noderive.summary" SUITE_LANE=test-lane \
    bash "$RECON" "$GREEN" "$TMP/noderive.exit" > "$TMP/noderive.out" 2>&1; echo $? > "$TMP/noderive.rc" )
expect noderive "exits 0"                        rc      '^0$'
expect noderive "says the denominator is unknown" summary '^🔴 \*\*Denominator unknown: suite-expected-results: cargo metadata --no-deps failed'
expect noderive "still prints the counts"        out     '^passed=2411 failed=0 ignored=15$'
expect noderive "shows the bare count"           summary '\| test result sets written \| \*\*143\*\* suite-expected-results'

# ── 9. The derivation itself, on a tiny workspace with a known shape. ─────────
# lib (test + doctest) + bin + tests/one.rs = 4; a bin behind a non-default
# feature is NOT counted; a `test = false` lib target is not counted but its
# doc-tests still are. Needs cargo; if it is missing this FAILS rather than
# skips — a suite that silently skips its only end-to-end case is #636 again.
if command -v cargo >/dev/null 2>&1; then
  W="$TMP/ws"; mkdir -p "$W/a/src" "$W/a/tests" "$W/b/src/bin" "$W/c/src"
  cat > "$W/Cargo.toml" <<'T'
[workspace]
members = ["a", "b", "c"]
resolver = "2"
T
  cat > "$W/a/Cargo.toml" <<'T'
[package]
name = "a"
version = "0.0.0"
edition = "2021"
T
  : > "$W/a/src/lib.rs"; : > "$W/a/src/main.rs"; : > "$W/a/tests/one.rs"
  cat > "$W/b/Cargo.toml" <<'T'
[package]
name = "b"
version = "0.0.0"
edition = "2021"

[features]
default = ["on"]
on = []
off = []

[[bin]]
name = "counted"
path = "src/bin/counted.rs"
required-features = ["on"]

[[bin]]
name = "skipped"
path = "src/bin/skipped.rs"
required-features = ["off"]
T
  : > "$W/b/src/lib.rs"; : > "$W/b/src/bin/counted.rs"; : > "$W/b/src/bin/skipped.rs"
  cat > "$W/c/Cargo.toml" <<'T'
[package]
name = "c"
version = "0.0.0"
edition = "2021"

[lib]
test = false
T
  : > "$W/c/src/lib.rs"
  # a: lib + bin + tests/one + doctest = 4; b: lib + counted + doctest = 3; c: doctest only = 1.
  got=$(bash "$EXPECT" "$W" 2> "$TMP/derive.err"); rc=$?
  if [ "$rc" = 0 ] && [ "$got" = 8 ]; then PASS=$((PASS + 1)); else
    FAIL=$((FAIL + 1)); echo "FAIL [derive] wanted 8 (rc 0), got '$got' (rc $rc)"; sed 's/^/      | /' "$TMP/derive.err"; fi
  if grep -q 'not counted, required-features off by default: b/skipped' "$TMP/derive.err"; then PASS=$((PASS + 1)); else
    FAIL=$((FAIL + 1)); echo "FAIL [derive] did not name the skipped bin"; sed 's/^/      | /' "$TMP/derive.err"; fi
  if grep -q '^suite-expected-results: 5 test binaries + 3 doc-test sets$' "$TMP/derive.err"; then PASS=$((PASS + 1)); else
    FAIL=$((FAIL + 1)); echo "FAIL [derive] wanted '5 test binaries + 3 doc-test sets'"; sed 's/^/      | /' "$TMP/derive.err"; fi
  # No manifest ⇒ non-zero and a named reason, never a number.
  if out=$(bash "$EXPECT" "$TMP" 2>&1); then FAIL=$((FAIL + 1)); echo "FAIL [derive] printed '$out' for a directory with no manifest"; else PASS=$((PASS + 1)); fi
else
  FAIL=$((FAIL + 1)); echo "FAIL [derive] cargo not on PATH — the derivation case cannot run, and it must not be skipped silently"
fi

echo
echo "suite-reconcile: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
