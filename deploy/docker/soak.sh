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
# LOCALHOST/DOCKER ONLY — no WAN-latency claims. Real RandomX light, WallClock,
# frozen 75 s block time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE="$SCRIPT_DIR/docker-compose.yml"
NET_MAIN=qumbra_t0
NET_SIDEB=qumbra_t0_sideb
PINNED_GENESIS=4a75b3b8a80122cbbc35867df17bd14f19054658b511dbc45bcfa67053cfc2c3
NODES=(node0 node1 node2 node3)

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

  teardown)
    dc down -v
    docker network rm "$NET_SIDEB" 2>/dev/null || true
    ;;

  *)
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
