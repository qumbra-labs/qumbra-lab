#!/usr/bin/env bash
# The acceptance suite's reconciliation — the step that turns `suite.log` into
# the job-summary table a human reads at acceptance (CLAUDE.md §5). Extracted
# from acceptance-graviton.yml's inline `run:` in lab #691 so that it can be
# exercised against saved logs (../tests/suite-reconcile/), which is the only
# way its truncation branch is ever tested: nobody deliberately times out a
# 50-minute Graviton run to see a sentence print.
#
#   reconcile-suite.sh <suite.log> <suite.exit>
#
#   suite.log   what `cargo test ... 2>&1 | tee suite.log` wrote. Absent ⇒ the
#               suite step died before tee started; said so, nothing else.
#   suite.exit  ONE line, cargo's exit code, written by the suite step AFTER
#               cargo returned. ABSENT ⇒ cargo never returned: the step was
#               cut off by `timeout-minutes`, an OOM kill of cargo itself, a
#               runner eviction or a manual cancel. This file is the truncation
#               detector's primary signal — see WHAT THIS STEP DETECTS.
#
#   env  SUITE_EXPECTED_RESULTS  override the derived denominator (tests only)
#        SUITE_LANE              heading suffix, default "graviton-rig"
#        GITHUB_STEP_SUMMARY     where the table goes; stdout if unset
#        GITHUB_SHA              for the heading
#
# WHAT THIS STEP RULES ON: nothing. Pass/fail is the SUITE step's exit code —
# `set -o pipefail` plus tee means cargo's own exit code IS that step's exit
# code, with no launcher in between. Everything here is a human cross-check
# and is deliberately not allowed to turn a green suite red. This script exits
# 0 on every path, including the loud ones. (Rationale inherited from the
# retired suite-arm64.yml (removed 2026-08-21, e9bf14c), restated here
# because that file is gone:
# `panicked at` is reachable on a GREEN run — this workspace has
# `#[should_panic]` tests, and a panic raised on a spawned thread escapes the
# harness's output capture — so a gate that CAN fire on a correct run teaches
# the reader to override it, the alarm-nobody-reads failure prefilter.yml
# already refuses once for clippy.)
#
# WHAT THIS STEP DETECTS (lab #691). Before #691 the suite ran without
# `--no-fail-fast`, cargo stopped at the first failing BINARY, and this step
# printed the partial sums in the same table, with the same shape, as a
# complete run: run 32922325707 executed 25 of 143 result sets and printed
# `passed=836 failed=1 ignored=3` with nothing saying that ~1,600 tests never
# ran. `--no-fail-fast` closes the cargo-level case; the cases it cannot close
# — timeout, OOM, eviction — end the step without cargo returning, and this
# step still runs (`if: always()`), so it has to SAY when the numbers are
# partial. Three signals, cheapest first, none of them a checked-in constant:
#
#   1. suite.exit present?      cargo returned ⇔ with --no-fail-fast, every
#                               target that built was attempted.
#   2. `test result:` count vs  the denominator, derived from the manifests by
#      the expected count        suite-expected-results.sh (cargo metadata,
#                               no build). Catches a stopped-clean-between-
#                               binaries cut, a build failure (0 results), and
#                               a selection-rule drift — in the LOUD direction.
#   3. `Running`+`Doc-tests`    a binary that started and never reported is
#      count vs `test result:`  named, so the reader knows where it stopped.
#
# The failure mode this must never have is silence: a detector that cannot
# derive its denominator says so in red rather than printing nothing (lab
# #402's "probes must fail loudly").
set -uo pipefail

log="${1:?usage: reconcile-suite.sh <suite.log> <suite.exit>}"
exitfile="${2:?usage: reconcile-suite.sh <suite.log> <suite.exit>}"
lane="${SUITE_LANE:-graviton-rig}"
sha="${GITHUB_SHA:-}"
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -f "$log" ]; then
  {
    echo "## Workspace suite — $lane"
    echo
    echo "🔴 **No \`suite.log\`.** The suite step did not get far enough to write one," \
         "so there is nothing to reconcile — this is not a zero-failure run."
  } >> "$summary"
  echo "::error::suite.log absent — the suite step did not start cargo; this is not a zero-failure run"
  exit 0
fi

# ── the counts ─────────────────────────────────────────────────────────────
# Cargo colours its status words: the literal text is `\e[1m\e[92m     Running\e[0m unittests …`,
# so anything anchored on `^ *Running ` must strip escapes first or it counts
# zero and the detector is silent — exactly the defect one level up.
plain=$(mktemp); trap 'rm -f "$plain"' EXIT
sed $'s/\x1b\\[[0-9;]*m//g' "$log" > "$plain"

# grep -c exits 1 on zero matches; that is a count, not an error.
results_c=$(grep -cE '^test result:' "$plain" || true)
running_c=$(grep -cE '^ *(Running|Doc-tests) ' "$plain" || true)
fail_c=$(grep -c 'FAILED' "$plain" || true)
panic_c=$(grep -c 'panicked at' "$plain" || true)
err_c=$(grep -cE '^error' "$plain" || true)
mark() { [ "$1" = "0" ] && echo "OK" || echo "SEE LOG"; }

# Sums. `test result: ok. 11 passed; 0 failed; 0 ignored; …` — fields 4/6/8.
read -r passed failed ignored < <(grep -E '^test result:' "$plain" \
  | awk '{p+=$4; f+=$6; i+=$8} END {print p+0, f+0, i+0}')

# Signal 1 — did cargo return?
cargo_returned=0; cargo_rc=""
if [ -f "$exitfile" ]; then
  cargo_returned=1
  cargo_rc=$(tr -dc '0-9' < "$exitfile")
fi

# Signal 2 — the denominator. An override is for the fixture tests only.
expected=""; expected_note=""
if [ -n "${SUITE_EXPECTED_RESULTS:-}" ]; then
  expected="$SUITE_EXPECTED_RESULTS"
  expected_note="(SUITE_EXPECTED_RESULTS override)"
else
  derive_err=$(mktemp); trap 'rm -f "$plain" "$derive_err"' EXIT
  if expected=$("$here/suite-expected-results.sh" 2>"$derive_err"); then
    expected_note="($(grep -o '[0-9]* test binaries + [0-9]* doc-test sets' "$derive_err" || echo derived), from \`cargo metadata\`)"
  else
    expected=""
    expected_note="$(tr '\n' ' ' < "$derive_err")"
  fi
fi

# Signal 3 — the binary that started and never reported.
last_started=""
if [ "$running_c" -gt "$results_c" ]; then
  last_started=$(grep -E '^ *(Running|Doc-tests) ' "$plain" | tail -1 | sed -E 's/^ *//; s/ \(.*//')
fi

# ── the verdict on completeness (advisory; never an exit code) ─────────────
# complete   cargo returned AND (denominator unknown OR results == expected)
# truncated  cargo did not return
# incomplete cargo returned but results != expected
verdict="complete"
if [ "$cargo_returned" = 0 ]; then
  verdict="truncated"
elif [ -n "$expected" ] && [ "$results_c" != "$expected" ]; then
  verdict="incomplete"
fi

of_expected="$results_c"
[ -n "$expected" ] && of_expected="$results_c of $expected expected"
missing=""
[ -n "$expected" ] && [ "$expected" -gt "$results_c" ] && missing=$((expected - results_c))

loud() {  # $1 = one-line message; goes to the summary AND to an annotation
  echo "🔴 **$1**" >> "$summary"
  echo >> "$summary"
  echo "::error::$1"
}

{
  echo "## Workspace suite — $lane${sha:+ (\`${sha:0:12}\`)}"
  echo
  echo "\`cargo test --release --workspace --locked --no-fail-fast -- --test-threads=1\`"
  echo
  echo "### Completeness"
  echo
  echo '| | |'
  echo '|---|---|'
  if [ "$cargo_returned" = 1 ]; then
    echo "| cargo returned | yes, exit $cargo_rc |"
  else
    echo "| cargo returned | **NO** — no \`suite.exit\`; the step was cut off |"
  fi
  echo "| test result sets written | **$of_expected** $expected_note |"
  [ -n "$last_started" ] && echo "| started, never reported | \`$last_started\` |"
  echo
} >> "$summary"

case "$verdict" in
  truncated)
    msg="TRUNCATED — this is not a zero-failure run. cargo did not return: the suite step was cut off (timeout-minutes, an OOM kill, a runner eviction or a cancel) after $of_expected test result sets were written"
    [ -n "$missing" ] && msg="$msg; $missing never reported"
    [ -n "$last_started" ] && msg="$msg. It stopped inside \`$last_started\`"
    loud "$msg. The counts below cover only what ran."
    ;;
  incomplete)
    if [ "$results_c" = 0 ]; then
      loud "NO TEST RESULTS — this is not a zero-failure run. cargo returned (exit $cargo_rc) without running a single test binary: the tree did not build. $expected result sets were expected."
    elif [ -n "$missing" ]; then
      loud "INCOMPLETE — this is not a zero-failure run. cargo returned (exit $cargo_rc) but wrote only $of_expected test result sets; $missing never reported. With --no-fail-fast this should not happen — read the log before trusting the counts below."
    else
      loud "MORE RESULTS THAN EXPECTED ($of_expected). The counts below are complete, but the denominator rule in suite-expected-results.sh is stale — fix it, do not ignore it."
    fi
    ;;
  complete)
    if [ -z "$expected" ]; then
      loud "Denominator unknown: $expected_note — completeness judged on cargo returning only (exit $cargo_rc, $results_c result sets)."
    elif [ "$cargo_rc" = 0 ]; then
      echo "✅ Complete and green: cargo returned 0 and every expected test result set is present." >> "$summary"
      echo >> "$summary"
    else
      echo "🟠 Complete but RED: cargo exited $cargo_rc, and every expected test result set is present —" \
           "with \`--no-fail-fast\` that means the failures below are ALL of them, not the first one." >> "$summary"
      echo >> "$summary"
    fi
    ;;
esac

# ── the table, as before ───────────────────────────────────────────────────
{
  echo "### Reconciliation"
  echo
  echo '| | passed | failed | ignored |'
  echo '|---|---:|---:|---:|'
  echo "| **total** | **$passed** | **$failed** | **$ignored** |"
  echo
  echo "The coordinator's arithmetic is \`total == main's baseline + this branch's new tests\`."
  echo "**This job does not know the baseline and does not assert one** — it reports the"
  echo "left-hand side only. The per-binary table below is here so a delta is attributable"
  echo "to a crate instead of to the workspace."
  echo
  echo "### Negatives"
  echo
  echo '| grep | count | |'
  echo '|---|---:|---|'
  echo "| \`FAILED\` (case-sensitive) | $fail_c | $(mark "$fail_c") |"
  echo "| \`panicked at\` | $panic_c | $(mark "$panic_c") |"
  echo "| \`^error\` | $err_c | $(mark "$err_c") |"
  echo
  echo "Advisory, not a gate — \`panicked at\` is reachable on a green run (\`#[should_panic]\`"
  echo "tests, panics on spawned threads escaping the harness's capture; see this script's"
  echo "header). With \`--no-fail-fast\` a red run lists EVERY failure, so these counts are"
  echo "larger than they used to be on a red run. **Pass/fail is the suite step's exit code.**"
  echo
  echo "### Cost of the run"
  echo
  echo '```'
  grep -E 'Maximum resident set size' "$plain" || echo "(time -v line not captured)"
  grep -E 'Elapsed \(wall clock\)' "$plain" || true
  echo '```'
  echo
  echo "<details><summary>Per-binary counts</summary>"
  echo
  echo '| binary | passed | failed | ignored |'
  echo '|---|---:|---:|---:|'
  awk '
    /^ *(Running|Doc-tests)/ { bin = $0; sub(/^ */, "", bin); next }
    /^test result:/ {
      name = bin
      if (match(name, /\/deps\/[^)]*/))
        name = substr(name, RSTART + 6, RLENGTH - 6)
      if (name == "") name = "(unattributed)"
      print "| `" name "` | " $4 " | " $6 " | " $8 " |"
    }
  ' "$plain"
  echo
  echo "</details>"
} >> "$summary"

# The step log gets the short form, as before, plus the verdict.
echo "=== 0. completeness ==="
echo "verdict=$verdict cargo_returned=$cargo_returned cargo_exit=${cargo_rc:-none} results=$of_expected running=$running_c"
echo "=== 2. counts ==="
echo "passed=$passed failed=$failed ignored=$ignored"
echo "(the rig baseline is compared by the coordinator at acceptance,"
echo " not asserted here -- this job reports, it does not rule)"
echo "=== negatives ==="
echo "FAILED(cs)=$fail_c  panicked=$panic_c  ^error=$err_c"
echo "=== 1. peak memory ==="
grep -E 'Maximum resident set size' "$plain" || echo "(time -v line not captured)"
echo "=== 3. wall time ==="
grep -E 'Elapsed \(wall clock\)' "$plain" || true
exit 0
