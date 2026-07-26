#!/usr/bin/env bash
#
# Phase B-lite soak driver (M10-T0-3, issue #64 amendment 3) — the docker/localhost
# rehearsal of the Phase-B protocol. Each scenario is a subcommand so the operator
# runs them one at a time and reads the telemetry between steps (STOP-POINT
# discipline: on any consensus misbehavior, STOP and preserve state — do not
# patch-and-continue).
#
#   soak.sh rehearsal            build + genesis rehearsal (assert pinned hash) + up
#   soak.sh status               one telemetry snapshot per node
#   soak.sh sample <secs> [ivl]  print each node's telemetry every <ivl>s for <secs>
#   soak.sh latejoiner           node3 joins late → sync-from-genesis
#   soak.sh restart <node>       stop+start a node → open==replay on its volume
#   soak.sh partition            true 2+2 split (docker network disconnect)
#   soak.sh heal                 reconnect the partition → converge + finality resume
#   soak.sh committee-stall      stop 3 key-holders → Degraded (quorum lost)
#   soak.sh committee-recover    restart them → T0-2 catch-up → Final
#   soak.sh teardown             docker compose down -v (destroys volumes)
#
# HALT-HEIGHT UPGRADE DRILL (issue #74). Run in order; each prints its own
# assertions and STOPS on a violation. H = 16 (on the cadence grid of 8).
#
#   soak.sh halt-arm             fresh net: node0/1/2 on the ARMED binary, node3 on
#                                the plain v1.0 binary (the §4 old-binary miner —
#                                it never deployed the halt, so it never halts).
#                                Runs to H and asserts the halt.
#   soak.sh halt-drill-b         (b) N2: upgrade only node0+node1 (11 keys < 15)
#                                → finality must NOT resume
#   soak.sh halt-drill-a         (a) H3: upgrade node2 too (16 keys ≥ 15) → finality
#                                resumes past H while node3's old-rule branch grows
#                                and NEVER finalizes
#   soak.sh halt-drill-c         (c) H4: start node2 on the no-revision binary →
#                                must REFUSE to start
#   soak.sh halt-drill-d         (d) N1: fresh net, all nodes on the CANCELLED
#                                binary → mines straight through H, never halts
#   soak.sh halt-status          per-node halt view (tip / final / regime / halt)
#   soak.sh halt-evidence        append full telemetry + raw refusal reasons to
#                                docs/m11-halt-height-evidence.log
#
# LOCALHOST/DOCKER ONLY — no WAN-latency claims. Real RandomX light, WallClock,
# frozen 75 s block time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="$SCRIPT_DIR/docker-compose.yml"
NET_MAIN=qumbra_t0
NET_SIDEB=qumbra_t0_sideb
PINNED_GENESIS=4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3
NODES=(node0 node1 node2 node3)
# The halt height compiled into the drill binaries (release.rs DRILL_HALT_HEIGHT).
# On the checkpoint-cadence grid (16 = 2 x 8), deliberately low so each drill is
# minutes. Keep in step with the Rust constant.
HALT_H=16

dc()  { docker compose -f "$COMPOSE" "$@"; }
cid() { dc ps -q "$1"; }

die() { echo "soak: $*" >&2; exit 1; }

# RIG DISCIPLINE — refuse to start heavy docker work while the b4 bench runs.
guard_rig() {
  if pgrep -f qlab_bench >/dev/null 2>&1; then
    die "b4 bench (qlab_bench) is running — do NOT build/up now (OOM risk). Wait it out."
  fi
}

# The latest TELEMETRY line a node has emitted (stdout, captured by docker logs).
# `|| true`: a node with no telemetry yet (just wiped / not started) makes grep
# exit non-zero, which would abort the script under `set -o pipefail`.
latest() { dc logs --no-log-prefix "$1" 2>/dev/null | grep '^TELEMETRY' | tail -1 || true; }

# Extract key=value from a telemetry line.
field() { sed -n "s/.* $2=\([^ ]*\).*/\1/p" <<<"$1"; }

snapshot() {
  for n in "${NODES[@]}"; do
    local line; line="$(latest "$n")"
    if [[ -z "$line" ]]; then
      printf '  %-6s (no telemetry yet / down)\n' "$n"
    else
      printf '  %-6s tip=%-4s final=%-4s stall=%-3s diff=%-6s peers=%-2s regime=%s\n' \
        "$n" "$(field "$line" tip)" "$(field "$line" final)" \
        "$(field "$line" stall)" "$(field "$line" diff)" \
        "$(field "$line" peers)" "$(field "$line" regime)"
    fi
  done
}

# Wait until a node's tip reaches at least H (or timeout secs). Returns 0/1.
wait_tip() {
  local node="$1" want="$2" timeout="${3:-300}" waited=0
  while (( waited < timeout )); do
    local line tip; line="$(latest "$node")"; tip="$(field "$line" tip)"
    [[ -n "$tip" ]] && (( tip >= want )) && return 0
    sleep 5; waited=$((waited + 5))
  done
  return 1
}

# Assert every named node is halted at the boundary, with an IDENTICAL finalized
# tip. Any disagreement here is a stop-point, not a retry.
halt_assert_halted() {
  local ref_tip="" ref_final=""
  for n in "$@"; do
    local line; line="$(latest "$n")"
    [[ -n "$line" ]] || die "$n produced no telemetry — capture logs, STOP"
    local tip final regime halt
    tip="$(field "$line" tip)"; final="$(field "$line" final)"
    regime="$(field "$line" regime)"; halt="$(field "$line" halt)"
    [[ "$halt" == "$HALT_H" ]] || die "$n reports halt=$halt, expected $HALT_H — wrong binary? STOP."
    [[ "$tip" == "$HALT_H" ]]       || die "$n tip=$tip but the halt height is $HALT_H — an armed node must not pass it. STOP."
    [[ "$regime" == "Halted" ]]       || die "$n regime=$regime, expected Halted. If it is 'Halting', H's checkpoint has not
   finalized — that is the honest signal NOT to swap binaries yet. Wait, then re-check."
    if [[ -z "$ref_tip" ]]; then ref_tip="$tip"; ref_final="$final"; fi
    [[ "$tip" == "$ref_tip" && "$final" == "$ref_final" ]]       || die "$n disagrees about the boundary (tip=$tip final=$final vs $ref_tip/$ref_final). STOP."
  done
  echo "   ✓ all armed nodes report regime=Halted at an IDENTICAL finalized tip $ref_tip/$ref_final"
}

# The invariant the whole mechanism exists to protect: no two nodes may report
# different finalized blocks at the same height. Telemetry carries heights, not
# hashes, so this checks the strongest thing it can — that no node's finalized head
# is ahead of a peer's on a branch the peer rejected — and points at the deeper
# check when heights alone cannot settle it.
halt_assert_no_conflicting_finality() {
  local upgraded=(node0 node1 node2)
  local ref=""
  for n in "${upgraded[@]}"; do
    local f; f="$(field "$(latest "$n")" final)"
    [[ -n "$f" && "$f" != "-" ]] || continue
    if [[ -z "$ref" ]]; then ref="$f"; continue; fi
    local lo=$(( f < ref ? f : ref ))
    (( lo >= HALT_H )) || die "an upgraded node finalized BELOW the boundary — reorg past
   finality. STOP EVERYTHING and preserve state."
  done
  echo "   ✓ no upgraded node finalized below the boundary (no reorg past a finalized checkpoint)"
}

# WHICH LAYER refused an old-binary block (issue #74). The two counters are on
# every telemetry line and mean different things about the upgrade:
#   hignore — this release is HALTED and did not act on the block. The block was not
#             judged invalid and the sender is NOT penalised (release layer).
#   powrej  — the header failed the PoW target. Above an upgrade boundary that is the
#             post-halt rule domain biting: the block is invalid on the upgraded net
#             and never reaches fork choice (header-validation layer).
# §4 as written describes the second kind of outcome. Report what the logs actually
# show; do NOT paraphrase one as the other.
# Where the drill parks its evidence. The counters are PER-PROCESS and reset when a
# container is recreated (which a binary swap necessarily does), so the before/after
# pair has to be captured to disk — a post-swap process legitimately reports
# hignore=0 because it is a new process, not because nothing was ignored.
EVID_DIR="$SCRIPT_DIR/../../docs"
EVID="$EVID_DIR/m11-halt-height-evidence.log"

# Append a labelled snapshot of every node's raw telemetry line to the evidence log.
halt_record() {
  local label="$1"
  { echo "=== $label ==="
    for n in "${NODES[@]}"; do printf '%s %s\n' "$n" "$(latest "$n")"; done
  } >> "$EVID"
  echo "   (evidence appended: $label → ${EVID#"$SCRIPT_DIR/../../"})"
}

# Save the pre-swap counter values so the post-swap comparison is against a real
# recorded number rather than a remembered one.
halt_save_counters() {
  : > "$SCRIPT_DIR/.halt-preswap"
  for n in "${NODES[@]}"; do
    local line; line="$(latest "$n")"
    printf '%s %s %s\n' "$n" "$(field "$line" hignore)" "$(field "$line" powrej)" \
      >> "$SCRIPT_DIR/.halt-preswap"
  done
}
halt_preswap() {  # halt_preswap <node> <hignore|powrej>
  local n="$1" which="$2"
  local col=2; [[ "$which" == "powrej" ]] && col=3
  awk -v n="$n" -v c="$col" '$1 == n { print $c }' "$SCRIPT_DIR/.halt-preswap" 2>/dev/null
}

halt_report_layers() {
  echo "   -- refusal layers (hignore = release layer · powrej = header-validation layer) --"
  for n in "${NODES[@]}"; do
    local line; line="$(latest "$n")"
    [[ -n "$line" ]] || continue
    printf '     %-6s hignore=%-5s powrej=%-5s   %s\n' \
      "$n" "$(field "$line" hignore)" "$(field "$line" powrej)" \
      "$(field "$line" regime)"
  done
  echo "     (raw rejection reasons: dc logs <node> | grep -E 'above halt height|invalid header')"
}

cmd="${1:-}"; shift || true
case "$cmd" in

  rehearsal)
    guard_rig
    echo "== genesis rehearsal =="
    echo "-- building image (first Linux build of randomx-rs + qumbra-node) --"
    dc build
    echo "-- starting all 4 nodes (genesis-init runs first via depends_on) --"
    dc up -d node0 node1 node2 node3
    # genesis-init has exited (service_completed_successfully); read the hash it
    # printed ("init: genesis hash <hash>") from its captured logs.
    got="$(dc logs --no-log-prefix genesis-init 2>/dev/null \
            | sed -n 's/^init: genesis hash //p' | tail -1 | tr -d '\r')"
    echo "   in-container genesis hash: ${got:-<unread>}"
    echo "   pinned T0 genesis hash:    $PINNED_GENESIS"
    [[ "$got" == "$PINNED_GENESIS" ]] \
      || die "GENESIS HASH MISMATCH — in-container genesis is not the frozen T0 genesis. STOP."
    echo "   ✓ in-container genesis == pinned T0 genesis (4a75b3b8…c2c3)"
    echo "   nodes up; watch blocks with: $0 sample 200"
    ;;

  status)  snapshot ;;

  sample)
    secs="${1:-180}"; ivl="${2:-30}"; waited=0
    while (( waited <= secs )); do
      echo "== t+${waited}s =="; snapshot; echo
      sleep "$ivl"; waited=$((waited + ivl))
    done
    ;;

  latejoiner)
    echo "== late-joiner sync-from-genesis (node3) =="
    # True from-genesis join: wipe node3's DATA IN PLACE (not the volume/container),
    # then `dc start` — reusing the existing container keeps its network endpoint
    # stable, so its one-shot startup dials resolve node0..2 (recreating the
    # container recreates the network and the dials fire during the blip → they
    # fail with no re-dial; that is finding #F-dial in the run doc).
    dc stop node3 2>/dev/null || true
    docker run --rm -v qumbra-t0-lite_data3:/d alpine sh -c 'rm -rf /d/* /d/..?* 2>/dev/null || true'
    echo "-- node3 stopped + data wiped in place; letting node0..2 advance --"
    wait_tip node0 5 400 || echo "   (warn) node0 did not reach tip 5 in time"
    echo "   before join:"; snapshot
    echo "-- starting node3 fresh (must sync from genesis) --"
    dc start node3
    lead="$(field "$(latest node0)" tip)"; lead="${lead:-5}"
    if wait_tip node3 "$lead" 400; then
      echo "   ✓ node3 synced to tip >= $lead"
    else
      echo "   (finding) node3 did not catch up to $lead within 400s — capture logs"
    fi
    snapshot
    ;;

  restart)
    node="${1:?restart needs a node name (e.g. node1)}"
    echo "== mining-node restart: $node (open==replay on its volume) =="
    before="$(field "$(latest "$node")" tip)"
    echo "   tip before stop: ${before:-?}"
    dc stop "$node"
    sleep 3
    dc start "$node"
    sleep 8
    after="$(field "$(latest "$node")" tip)"
    echo "   tip after restart: ${after:-?}"
    if [[ -n "$before" && -n "$after" ]] && (( after >= before )); then
      echo "   ✓ open==replay: tip persisted (>= pre-restart height) from the disk log"
    else
      echo "   (finding) tip did not persist across restart — inspect the block log"
    fi
    ;;

  partition)
    echo "== 2+2 partition (A={node0,node1} 11 keys | B={node2,node3} 10 keys) =="
    echo "   both sides < 15 quorum ⇒ finality MUST stall on both sides (expected, not a bug)"
    docker network inspect "$NET_SIDEB" >/dev/null 2>&1 || docker network create "$NET_SIDEB" >/dev/null
    # keep the B-side pair talking to each other over sideb, then cut them off qumbra
    docker network connect "$NET_SIDEB" "$(cid node2)"
    docker network connect "$NET_SIDEB" "$(cid node3)"
    docker network disconnect "$NET_MAIN" "$(cid node2)"
    docker network disconnect "$NET_MAIN" "$(cid node3)"
    echo "   partitioned. sample both sides:"; snapshot
    echo "   watch finality: stall should GROW and regime flip to Degraded on both sides"
    ;;

  heal)
    echo "== heal the partition =="
    docker network connect "$NET_MAIN" "$(cid node2)" || true
    docker network connect "$NET_MAIN" "$(cid node3)" || true
    docker network disconnect "$NET_SIDEB" "$(cid node2)" 2>/dev/null || true
    docker network disconnect "$NET_SIDEB" "$(cid node3)" 2>/dev/null || true
    echo "   reconnected to $NET_MAIN. periodic re-dial (M10-T0-5 / S9) reconnects the split"
    echo "   peers WITHOUT a restart; fork-choice converges and cross-node vote aggregation"
    echo "   resumes → finality (final=) should advance again on both sides within ~1–2 cadences."
    snapshot
    ;;

  committee-stall)
    echo "== committee stall: stop node1+node2+node3 (16 keys offline; node0's 6 < 15) =="
    dc stop node1 node2 node3
    echo "   node0 keeps mining (PoW) but cannot finalize — regime → Degraded, stall grows."
    snapshot
    ;;

  committee-recover)
    echo "== T0-2 recovery: restart the finalizers → committee re-forms → catch-up =="
    dc start node1 node2 node3
    echo "   21 keys reachable again; checkpoints should resume and finalize the backlog."
    snapshot
    ;;


  # ── halt-height upgrade drill (issue #74) ─────────────────────────────────
  #
  # H is the DRILL_HALT_HEIGHT compiled into the drill binaries
  # (crates/qumbra-node/src/release.rs). Keep these in step.

  halt-status)
    echo "== halt view =="
    for n in "${NODES[@]}"; do
      line="$(latest "$n")"
      if [[ -z "$line" ]]; then
        printf '  %-6s (no telemetry yet / down)\n' "$n"
      else
        printf '  %-6s tip=%-4s final=%-4s regime=%-8s halt=%-4s hignore=%-4s powrej=%-4s peers=%s\n' \
          "$n" "$(field "$line" tip)" "$(field "$line" final)" \
          "$(field "$line" regime)" "$(field "$line" halt)" \
          "$(field "$line" hignore)" "$(field "$line" powrej)" "$(field "$line" peers)"
      fi
    done
    ;;

  halt-arm)
    guard_rig
    echo "== halt-height drill, phase 1: ARM =="
    echo "   node0/1/2 → qumbra-node-armed (halts at H=$HALT_H)"
    echo "   node3     → qumbra-node        (the §4 old-binary miner: it never"
    echo "               deployed the halt, so it will keep mining past H)"
    echo "   Destroying any previous net so the drill starts from genesis."
    dc down -v >/dev/null 2>&1 || true
    docker network rm "$NET_SIDEB" 2>/dev/null || true
    dc build
    NODE0_BIN=qumbra-node-armed NODE1_BIN=qumbra-node-armed \
    NODE2_BIN=qumbra-node-armed NODE3_BIN=qumbra-node \
      dc up -d node0 node1 node2 node3
    got="$(dc logs --no-log-prefix genesis-init 2>/dev/null \
            | sed -n 's/^init: genesis hash //p' | tail -1 | tr -d '\r')"
    [[ "$got" == "$PINNED_GENESIS" ]] \
      || die "GENESIS HASH MISMATCH — the drill must run on the frozen T0 genesis. STOP."
    echo "   ✓ genesis == pinned T0 genesis; the drill changes NO frozen value (H5)"
    echo "   waiting for tip $HALT_H (75 s blocks — roughly $((HALT_H * 75 / 60)) min)…"
    wait_tip node0 "$HALT_H" 2400 || die "node0 never reached H=$HALT_H — capture logs, STOP"
    sleep 90   # let H's checkpoint finalize and telemetry catch up
    "$0" halt-status
    halt_assert_halted node0 node1 node2
    halt_report_layers
    halt_record "phase 1 — armed nodes halted at H=$HALT_H"

    # LAYER SIGNATURE while halted: nothing may have been rejected at the
    # header-validation layer. A halted node has not judged anything invalid — it
    # has stopped. powrej > 0 here would mean a node is running rules it should not
    # have yet, i.e. the wrong binary.
    for n in node0 node1 node2; do
      pr="$(field "$(latest "$n")" powrej)"
      [[ "$pr" == "0" ]] \
        || die "$n reports powrej=$pr while HALTED — a halted node judges nothing invalid.
   That means it is running post-halt rules already. Wrong binary. STOP."
    done
    echo "   ✓ powrej=0 on every halted node — refusals are at the RELEASE layer only"
    # node3 never halts, so it must show no release-layer refusals at all.
    h3="$(field "$(latest node3)" hignore)"
    [[ "$h3" == "0" ]] \
      || die "node3 reports hignore=$h3 but it carries NO halt — wrong binary on node3. STOP."
    echo "   ✓ node3 hignore=0 — it is the un-armed old-binary miner, as intended"
    halt_save_counters
    echo "   ✓ phase 1 complete: the armed nodes are HALTED at a finalized boundary."
    echo "   next: $0 halt-drill-b"
    ;;

  halt-drill-b)
    echo "== DRILL (b) — N2, the ⅔ gate =="
    echo "   Upgrading ONLY node0 (6 keys) + node1 (5 keys) = 11 keys < quorum 15."
    echo "   Finality MUST NOT resume: a minority committee does not limp forward."
    NODE0_BIN=qumbra-node-resume NODE1_BIN=qumbra-node-resume \
    NODE2_BIN=qumbra-node-armed  NODE3_BIN=qumbra-node \
      dc up -d node0 node1
    echo "   observing for 4 minutes (≈3 block times + a cadence)…"
    sleep 240
    "$0" halt-status
    halt_record "drill (b) — 11/21 keys upgraded"
    # N2's assertion is that finality does not advance ABOVE THE BOUNDARY. It is
    # deliberately NOT "final is unchanged": the finality TRACKER is not persisted
    # (M10-T0-5 / S7 — it rebuilds from re-gossip), so a just-restarted node
    # legitimately reports final=- for a while. That is a restart artefact, not lost
    # finality; the chain's finalized head is intact on disk. Reading it as a
    # regression would be the wrong alarm, so the check is numeric and one-sided.
    for n in node0 node1; do
      f="$(field "$(latest "$n")" final)"
      if [[ "$f" =~ ^[0-9]+$ ]] && (( f > HALT_H )); then
        die "$n FINALIZED $f > H=$HALT_H with only 11/21 keys upgraded — N2 VIOLATED.
   STOP EVERYTHING and preserve state."
      fi
      printf '     %-6s final=%-4s (- = tracker rebuilding after restart, expected)\n' "$n" "$f"
    done
    echo "   ✓ finality did not advance past H=$HALT_H with 11/21 keys upgraded — the ⅔ gate holds."
    echo "   next: $0 halt-drill-a"
    ;;

  halt-drill-a)
    echo "== DRILL (a) — H3, the hybrid honesty case =="
    echo "   Upgrading node2 as well → 16 keys ≥ quorum 15, so finality may resume."
    echo "   node3 stays on the OLD binary and keeps mining past H. Per"
    echo "   committee-and-governance §4 that is EXPECTED, not a defect: its blocks"
    echo "   can never finalize, and the fork resolves to the checkpointed branch."
    old_tip_before="$(field "$(latest node3)" tip)"
    NODE0_BIN=qumbra-node-resume NODE1_BIN=qumbra-node-resume \
    NODE2_BIN=qumbra-node-resume NODE3_BIN=qumbra-node \
      dc up -d node2
    echo "   waiting for the upgraded net to finalize past H=$HALT_H (up to 15 min)…"
    waited=0
    while (( waited < 900 )); do
      f="$(field "$(latest node0)" final)"
      [[ -n "$f" && "$f" != "-" ]] && (( f > HALT_H )) && break
      sleep 15; waited=$((waited + 15))
    done
    "$0" halt-status
    f0="$(field "$(latest node0)" final)"
    f3="$(field "$(latest node3)" final)"
    t3="$(field "$(latest node3)" tip)"
    [[ -n "$f0" && "$f0" != "-" ]] || die "node0 reports no finalized head — capture logs, STOP"
    (( f0 > HALT_H )) \
      || die "finality did NOT resume past H with 16/21 keys upgraded — investigate before continuing"
    echo "   ✓ the checkpointed branch finalized past H (node0 final=$f0)"
    # The old miner: its branch GROWS…
    if [[ -n "$t3" ]] && (( t3 > HALT_H )); then
      echo "   ✓ the old-binary miner grew past H (node3 tip=$t3, was $old_tip_before) — §4 expected"
    else
      echo "   (finding) node3 did not grow past H (tip=$t3) — the (a) case did not materialise;"
      echo "             record this honestly rather than reading it as a pass."
    fi
    # …and NEVER finalizes above H.
    if [[ -n "$f3" && "$f3" != "-" ]] && (( f3 > HALT_H )); then
      die "🛑 STOP-POINT: the un-upgraded branch FINALIZED above H (node3 final=$f3). Two branches
   finalizing above the boundary is the exact failure this mechanism exists to prevent.
   Preserve state (do NOT teardown), capture 'dc logs' for all four nodes, and report."
    fi
    echo "   ✓ the old-binary branch never finalized above H (node3 final=$f3)"
    halt_assert_no_conflicting_finality
    halt_report_layers
    halt_record "drill (a) — after the swap"

    # LAYER SIGNATURE after the swap, at the precision the in-process drill asserts:
    #   pre-swap  (halted process):  hignore > 0, powrej = 0   → RELEASE layer
    #   post-swap (new process):     hignore = 0, powrej > 0   → HEADER-VALIDATION layer
    # The counters reset with the container, which is what makes the post-swap
    # hignore=0 meaningful rather than an artefact to explain away.
    echo "   -- layer transition (pre-swap values recorded at halt-arm) --"
    swap_evidence=0
    for n in node0 node1 node2; do
      pre_h="$(halt_preswap "$n" hignore)"; pre_p="$(halt_preswap "$n" powrej)"
      now_h="$(field "$(latest "$n")" hignore)"; now_p="$(field "$(latest "$n")" powrej)"
      printf '     %-6s pre: hignore=%-4s powrej=%-4s  →  post: hignore=%-4s powrej=%-4s\n' \
        "$n" "${pre_h:-?}" "${pre_p:-?}" "${now_h:-?}" "${now_p:-?}"
      [[ "$now_p" =~ ^[0-9]+$ ]] || continue
      if (( now_p > 0 )); then
        swap_evidence=1
        [[ "$now_h" == "0" ]] || echo "     (finding) $n powrej>0 AND hignore=$now_h — a resumed
     release carries no halt, so hignore must not climb after the swap. Investigate."
      fi
    done
    if (( swap_evidence == 1 )); then
      echo "   ✓ post-swap refusals are at the HEADER-VALIDATION layer (post-halt PoW domain)"
    else
      echo "   (finding) no upgraded node recorded powrej>0. Either node3's post-H blocks never"
      echo "             reached them, or the old branch was refused at some other layer."
      echo "             Record this honestly — the layer claim is NOT evidenced without it."
      echo "             Check: dc logs node0 | grep -E 'invalid header|above halt height'"
    fi
    echo "   next: $0 halt-drill-c"
    ;;

  halt-drill-c)
    echo "== DRILL (c) — H4, resume without a revision digest =="
    echo "   Starting node2 on qumbra-node-norev (resumes past H, carries NO revision)."
    echo "   It MUST refuse to start."
    dc stop node2 >/dev/null
    NODE0_BIN=qumbra-node-resume NODE1_BIN=qumbra-node-resume \
    NODE2_BIN=qumbra-node-norev  NODE3_BIN=qumbra-node \
      dc up -d node2 || true
    sleep 20
    out="$(dc logs --no-log-prefix --tail 40 node2 2>/dev/null || true)"
    echo "--- node2 output ---"; echo "$out"; echo "--------------------"
    if grep -q "carries NO revision" <<<"$out"; then
      echo "   ✓ the no-revision binary REFUSED to resume (H4)."
    else
      die "the no-revision binary did NOT refuse — H4 VIOLATED. STOP, preserve state."
    fi
    if docker inspect -f '{{.State.Running}}' "$(cid node2)" 2>/dev/null | grep -q true; then
      die "node2 is still RUNNING on the no-revision binary — H4 VIOLATED. STOP."
    fi
    echo "   restoring node2 to the proper upgrade binary…"
    NODE0_BIN=qumbra-node-resume NODE1_BIN=qumbra-node-resume \
    NODE2_BIN=qumbra-node-resume NODE3_BIN=qumbra-node \
      dc up -d node2
    echo "   next: $0 halt-drill-d   (destroys this net — capture evidence first)"
    ;;

  halt-drill-d)
    guard_rig
    echo "== DRILL (d) — N1, the stand-down =="
    echo "   Fresh net, ALL nodes on qumbra-node-cancel: the upgrade at H=$HALT_H was"
    echo "   stood down, so the net must mine and finalize straight through it."
    dc down -v >/dev/null 2>&1 || true
    docker network rm "$NET_SIDEB" 2>/dev/null || true
    NODE0_BIN=qumbra-node-cancel NODE1_BIN=qumbra-node-cancel \
    NODE2_BIN=qumbra-node-cancel NODE3_BIN=qumbra-node-cancel \
      dc up -d node0 node1 node2 node3
    want=$((HALT_H + 8))
    echo "   waiting for tip $want (past the cancelled height)…"
    wait_tip node0 "$want" 2400 || die "the cancelled net never reached $want — capture logs, STOP"
    sleep 60
    "$0" halt-status
    for n in "${NODES[@]}"; do
      line="$(latest "$n")"
      r="$(field "$line" regime)"; h="$(field "$line" halt)"; t="$(field "$line" tip)"
      [[ -n "$t" ]] || die "$n produced no telemetry — capture logs, STOP"
      [[ "$h" == "-" ]] || die "$n reports halt=$h — a CANCELLED upgrade must schedule no halt. STOP."
      if [[ "$r" == "Halting" || "$r" == "Halted" ]]; then
        die "$n reports regime=$r — a CANCELLED upgrade must never halt. STOP."
      fi
      (( t > HALT_H )) || die "$n tip=$t did not pass the cancelled height $HALT_H. STOP."
    done
    f="$(field "$(latest node0)" final)"
    [[ -n "$f" && "$f" != "-" ]] && (( f > HALT_H )) \
      || die "finality did not advance past the cancelled height (final=$f). STOP."
    echo "   ✓ the stand-down held: mined and finalized through H, never a halt regime."
    ;;

  halt-evidence)
    echo "== dumping halt-drill evidence to $EVID =="
    { echo "=== full telemetry history + refusal reasons, $(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
      for n in "${NODES[@]}"; do
        echo "--- $n telemetry ---"
        dc logs --no-log-prefix "$n" 2>/dev/null | grep '^TELEMETRY' || true
        echo "--- $n halt/refusal lines ---"
        dc logs --no-log-prefix "$n" 2>/dev/null \
          | grep -E 'halt-height|HALT|halt plan|revision:|refus|above halt height|invalid header' || true
      done
    } >> "$EVID"
    echo "   appended. Raw reasons are what the run doc's layer claim rests on."
    ;;

  teardown)
    dc down -v
    docker network rm "$NET_SIDEB" 2>/dev/null || true
    ;;

  *)
    sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
