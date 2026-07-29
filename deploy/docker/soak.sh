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
# LATENCY INJECTION (issue #107 step 1b). Run against a net that is already up.
#
#   soak.sh netem <delay_ms> [jit_ms]  install `tc netem` on every node's eth0,
#                                      then PROVE it took (qdisc + measured RTT)
#   soak.sh netem-show                 the qdisc + the measured RTT matrix
#   soak.sh netem-clear                remove it, and prove it is gone
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
# LOCALHOST/DOCKER. Real RandomX light, WallClock, frozen 75 s block time.
#
# LATENCY: the bridge is loopback-fast (sub-millisecond RTT) unless you inject delay
# with `netem` above. This used to read "no WAN-latency claims", which was true of the
# harness but became the reason a WAN-vs-local question could not be settled here
# (#107 step 1). What is true now:
#
#   * A run with NO netem is a ZERO-LATENCY run. Do not quote its numbers as WAN
#     numbers, and do not quote them as evidence ABOUT latency either — that was the
#     old disclaimer's real content and it still holds.
#   * A run WITH netem models an emulated, UNIFORM, symmetric delay. State it as
#     "<delay> ms one-way netem on every node (RTT ~<2*delay> ms)", never as "WAN".
#     The real T0 WAN is none of those things: its measured 68-223 ms RTT baseline is
#     per-pair and asymmetric, it carries jitter and loss this does not, and its hosts
#     are t4g.small Graviton VMs rather than containers on one machine.
#   * `netem` therefore answers "is this effect latency-SHAPED", not "does this match
#     the T0 net". A negative result under netem rules out delay-as-such; it does not
#     rule out the WAN.

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

# ── latency injection (issue #107 step 1b) ──────────────────────────────────
#
# THE ARGUMENT IS ONE-WAY DELAY, NOT RTT. `tc netem delay` delays a container's
# EGRESS, and every node carries the same qdisc, so a packet and its reply each pay
# it once: RTT ~= 2 x delay. `netem 100` models the ~200 ms end of the measured
# 68-223 ms T0 WAN RTT baseline, not the 100 ms end. Every command here prints both
# the one-way figure and the implied RTT, and then MEASURES the RTT, so nobody has
# to hold that factor of two in their head.
NETEM_DEV=eth0

netem_qdisc() { dc exec -T "$1" tc qdisc show dev "$NETEM_DEV" 2>&1 | tr -d '\r' | tr '\n' ' '; }

# Print every node's qdisc verbatim, and return non-zero if ANY node disagrees with
# what was asked for.
#   netem_check_qdisc <delay_ms>   expect netem at that delay
#   netem_check_qdisc ""           expect NO netem at all
netem_check_qdisc() {
  local want="$1" bad=0 q
  echo "   -- tc qdisc show dev $NETEM_DEV, per container --"
  for n in "${NODES[@]}"; do
    q="$(netem_qdisc "$n")"
    printf '     %-6s %s\n' "$n" "${q:-<no output>}"
    if [[ -z "$want" ]]; then
      if grep -q 'netem' <<<"$q"; then
        echo "     ^ $n STILL carries a netem qdisc"; bad=1
      fi
    else
      if ! grep -q 'netem' <<<"$q"; then
        echo "     ^ $n has NO netem qdisc"; bad=1
      elif ! grep -Eq "delay ${want}(\.0+)?ms" <<<"$q"; then
        echo "     ^ $n netem is present but its delay is not ${want}ms"; bad=1
      fi
    fi
  done
  return "$bad"
}

# The check that matters more than the qdisc: is the delay actually ON THE PATH?
# An installed qdisc on the wrong device, or on a device the container's traffic does
# not leave by, shows up green in `tc qdisc show` and changes nothing. Full 12-pair
# matrix, because a per-pair asymmetry would otherwise hide behind one node's average.
netem_rtt_matrix() {
  local out avg
  echo "   -- measured ICMP RTT, every ordered pair (5 pings, avg ms) --"
  for n in "${NODES[@]}"; do
    local row="     $n ->"
    for p in "${NODES[@]}"; do
      [[ "$n" == "$p" ]] && continue
      out="$(dc exec -T "$n" ping -q -c 5 -i 0.3 -W 5 "$p" 2>/dev/null || true)"
      avg="$(sed -n 's|.*= [0-9.]*/\([0-9.]*\)/.*|\1|p' <<<"$out" | tail -1)"
      row+=" $p=${avg:-FAIL}"
    done
    echo "$row"
  done
}

netem_report() {   # netem_report <delay_ms|""> <label>
  local want="$1" label="$2"
  echo "== netem: $label =="
  if [[ -n "$want" ]]; then
    echo "   one-way delay ${want}ms on every node  =>  expected pairwise RTT ~$((want * 2))ms"
  fi
  netem_check_qdisc "$want" \
    || die "the qdisc is NOT what was asked for (above). A run under a silently-absent
   netem produces a clean, confident answer that means nothing. STOP."
  echo "   ✓ every node's qdisc matches what was requested"
  netem_rtt_matrix
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
# different finalized blocks at the same height.
#
# UNTIL 2026-07-29 this was checked by proxy, because telemetry carried heights and
# no hashes — two nodes finalizing DIFFERENT checkpoints at the same height printed
# identical lines. Issue #84 put the finalized checkpoint's identity on the line
# (`fid`), so the condition is now expressible directly and this checks it directly.
# The height-based guard below is kept: it catches a reorg past finality, which is a
# different failure and still worth its own assertion.
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

  # THE CONDITION THIS FUNCTION IS NAMED AFTER. Same finalized height, different
  # identity, on two nodes = two checkpoints finalized at one height. That is the
  # most severe STOP-POINT this project has, and before #84 it was invisible.
  local i j missing=0 checked=0
  for (( i = 0; i < ${#upgraded[@]}; i++ )); do
    local ni="${upgraded[$i]}" li fi_h fi_d
    li="$(latest "$ni")"; fi_h="$(field "$li" final)"; fi_d="$(field "$li" fid)"
    [[ -n "$fi_h" && "$fi_h" != "-" ]] || continue
    if [[ -z "$fi_d" ]]; then missing=1; continue; fi
    for (( j = i + 1; j < ${#upgraded[@]}; j++ )); do
      local nj="${upgraded[$j]}" lj fj_h fj_d
      lj="$(latest "$nj")"; fj_h="$(field "$lj" final)"; fj_d="$(field "$lj" fid)"
      [[ -n "$fj_h" && "$fj_h" != "-" ]] || continue
      if [[ -z "$fj_d" ]]; then missing=1; continue; fi
      [[ "$fi_h" == "$fj_h" ]] || continue
      checked=$(( checked + 1 ))
      [[ "$fi_d" == "$fj_d" ]] || die "TWO DIFFERENT CHECKPOINTS FINALIZED AT HEIGHT $fi_h —
   $ni fid=$fi_d vs $nj fid=$fj_d. This is the R2 STOP-POINT. STOP EVERYTHING,
   preserve every container's logs and /opt/qumbra/data before touching anything."
    done
  done

  # An image without #84 prints no `fid`. Say that the check did not run rather than
  # printing a tick — a silent pass here is exactly the failure this whole comment
  # block exists to describe, arriving from the other direction.
  if (( missing == 1 )); then
    echo "   (finding) at least one node prints no fid= — this image predates issue #84,"
    echo "             so the same-height/different-identity check DID NOT RUN. Heights"
    echo "             agreeing is not evidence that the checkpoints agree."
  elif (( checked == 0 )); then
    echo "   (finding) no two upgraded nodes shared a finalized height at this sample, so"
    echo "             there was nothing to compare. Not a pass — re-sample."
  else
    echo "   ✓ every pair at a shared finalized height reports the same fid ($checked pair(s))"
  fi
}

# What this node's OWN keys signed, which is a different question from what it
# finalized — and the one that catches a split the finalized view cannot see.
#
# Observed live on 2026-07-29 at slot 3776: sixteen keys signed one variant and five
# signed another, yet all four nodes finalized the SAME checkpoint, because the
# minority finalizes the majority's. `fid` was identical everywhere; only `sid`
# differed. So a divergence here is NOT a stop condition — it is the normal cost of
# signing when the tip first touches a slot, and it is reported as a finding.
halt_report_signed_divergence() {
  local nodes=("$@") i j split=0 missing=0
  for (( i = 0; i < ${#nodes[@]}; i++ )); do
    local ni="${nodes[$i]}" li si_s si_d
    li="$(latest "$ni")"; si_s="$(field "$li" sslot)"; si_d="$(field "$li" sid)"
    if [[ -z "$si_s" || -z "$si_d" ]]; then missing=1; continue; fi
    [[ "$si_d" != "-" ]] || continue
    for (( j = i + 1; j < ${#nodes[@]}; j++ )); do
      local nj="${nodes[$j]}" lj sj_s sj_d
      lj="$(latest "$nj")"; sj_s="$(field "$lj" sslot)"; sj_d="$(field "$lj" sid)"
      [[ -n "$sj_s" && -n "$sj_d" && "$sj_d" != "-" ]] || continue
      [[ "$si_s" == "$sj_s" ]] || continue
      if [[ "$si_d" != "$sj_d" ]]; then
        split=1
        echo "   (finding) signed-variant split at slot $si_s: $ni sid=$si_d vs $nj sid=$sj_d"
      fi
    done
  done
  if (( missing == 1 )); then
    echo "   (finding) at least one node prints no sslot=/sid= — image predates issue #84;"
    echo "             the signed-variant check did not run."
  elif (( split == 0 )); then
    echo "   ✓ no signed-variant split among the sampled nodes"
  else
    echo "             ^ not a stop condition. Record it; it is the per-key burn shape."
  fi
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

# Normalise a telemetry `final=` field to an integer; `-` (nothing finalized) → -1.
fin_num() { local v="$1"; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo "-1"; }

# DRILL (a)'s real assertion: while the checkpointed branch keeps finalizing, the
# un-upgraded node's finality must STOP advancing.
#
# Early after the swap node3 can legitimately still be tracking the checkpointed
# branch's checkpoints (that is what `final=24, tip=23` was), so a single window in
# which node3 also advances is NOT a failure — it is an inconclusive window. Only a
# node3 that keeps pace across repeated windows would contradict §4. Being wrong in
# the other direction is how the original check earned a false STOP-POINT; this one
# reports "not demonstrated" rather than inventing a violation.
halt_assert_old_branch_finality_frozen() {
  local rounds=3 r win=1500
  for (( r = 1; r <= rounds; r++ )); do
    local f0a f3a; f0a="$(fin_num "$(field "$(latest node0)" final)")"
    f3a="$(fin_num "$(field "$(latest node3)" final)")"
    echo "   -- window $r/$rounds: waiting for the CHECKPOINTED branch to finalize again"
    echo "      (start: node0 final=$f0a · node3 final=$f3a)"
    local waited=0 f0b=$f0a
    while (( waited < win )); do
      f0b="$(fin_num "$(field "$(latest node0)" final)")"
      (( f0b > f0a )) && break
      sleep 15; waited=$((waited + 15))
    done
    if (( f0b <= f0a )); then
      echo "   (finding) the CHECKPOINTED branch did not finalize again within ${win}s"
      echo "             (node0 final stuck at $f0a). That is a finding about the upgraded"
      echo "             net, NOT about node3 — drill (a)'s freeze claim is untested here."
      return 0
    fi
    local f3b; f3b="$(fin_num "$(field "$(latest node3)" final)")"
    echo "      (end:   node0 final=$f0b · node3 final=$f3b)"
    if (( f3b == f3a )); then
      echo "   ✓ the old-binary branch's finality is FROZEN at $f3b while the checkpointed"
      echo "     branch advanced $f0a → $f0b. Its blocks can never finalize (§4)."
      # `final > tip` on the un-upgraded node is EXPECTED here — it tracked the
      # upgraded branch's checkpoint for a block it does not hold. Named so a reader
      # does not have to rediscover it; see issue #85.
      local t3; t3="$(field "$(latest node3)" tip)"
      if [[ "$t3" =~ ^[0-9]+$ ]] && (( f3b > t3 )); then
        echo "     note: node3 reports final=$f3b > tip=$t3. EXPECTED here — it finalized the"
        echo "           UPGRADED branch's checkpoint for a block it does not hold. Its"
        echo "           ChainState is untouched (set_finalized fails on an unknown block)."
        echo "           This is issue #85, not a fault of this drill."
      fi
      return 0
    fi
    echo "      node3 also advanced ($f3a → $f3b) — it is still TRACKING the checkpointed"
    echo "      branch (expected while the branches are inside the tally window). Not a"
    echo "      violation; retrying with a fresh window."
  done
  echo "   (finding) node3's finality kept pace across $rounds windows, so the freeze was"
  echo "             NOT demonstrated. This is NOT by itself a two-branch finalization —"
  echo "             telemetry cannot distinguish 'finalized the same checkpoint' from"
  echo "             'finalized a different one' (issue #84). Do not read it either way:"
  echo "             capture 'dc logs' for all four nodes and settle it by inspection."
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

  # ── latency injection (issue #107 step 1b) ────────────────────────────────

  netem)
    delay="${1:?netem needs a ONE-WAY delay in ms, e.g. 'netem 100' for a ~200 ms RTT}"
    jit="${2:-0}"
    [[ "$delay" =~ ^[0-9]+$ ]] || die "delay must be a whole number of ms, got '$delay'"
    [[ "$jit"   =~ ^[0-9]+$ ]] || die "jitter must be a whole number of ms, got '$jit'"
    spec="delay ${delay}ms"
    (( jit > 0 )) && spec="delay ${delay}ms ${jit}ms distribution normal"
    for n in "${NODES[@]}"; do
      # `replace` rather than `add`: idempotent, so re-running at a new delay does not
      # need a clear first and cannot leave two runs' qdiscs stacked.
      dc exec -T "$n" tc qdisc replace dev "$NETEM_DEV" root netem $spec \
        || die "tc failed on $n. Is NET_ADMIN granted (docker-compose.yml cap_add) and
   is this image new enough to carry iproute2 (Dockerfile)? A net brought up from an
   older image has neither, and every command here would then be a no-op."
      echo "   applied on $n: netem $spec"
    done
    netem_report "$delay" "applied (${spec})"
    echo
    echo "   The nodes were NOT restarted, so existing TCP connections keep running;"
    echo "   the delay applies from now on. Give the net a few telemetry cadences"
    echo "   before you start the window you intend to report."
    ;;

  netem-show)
    # Reports, never asserts: this is the command you run when you do not already know
    # what is installed, so "no netem" is an answer here rather than a failure.
    echo "== netem: current state =="
    any=0
    echo "   -- tc qdisc show dev $NETEM_DEV, per container --"
    for n in "${NODES[@]}"; do
      q="$(netem_qdisc "$n")"
      printf '     %-6s %s\n' "$n" "${q:-<no output>}"
      grep -q 'netem' <<<"$q" && any=1
    done
    if (( any == 0 )); then
      echo "   => no netem qdisc on any node: this is a ZERO-LATENCY run."
    else
      echo "   => netem is installed. The figure above is ONE-WAY; RTT is ~twice it."
    fi
    netem_rtt_matrix
    ;;

  netem-clear)
    for n in "${NODES[@]}"; do
      # `|| true`: deleting a root qdisc that was never added is not an error worth
      # aborting on — the post-condition below is what decides whether this worked.
      dc exec -T "$n" tc qdisc del dev "$NETEM_DEV" root 2>/dev/null || true
      echo "   cleared on $n"
    done
    netem_report "" "cleared"
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
    # Sample every 5 s for the arming phase: `regime=Halting` is a real but SHORT
    # interval (tip reaches H, then the 6/5/5/5 vote round closes), and at the 30 s
    # default it can open and close between two prints. Observability only.
    NODE0_BIN=qumbra-node-armed NODE1_BIN=qumbra-node-armed \
    NODE2_BIN=qumbra-node-armed NODE3_BIN=qumbra-node QUMBRA_SAMPLE_SECS=5 \
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

    # H2 defines Halting as a real interval — reached H, boundary not yet final.
    # On the 6/5/5/5 net no node can finalize H alone, so the vote round MUST
    # happen; at a 5 s sampling cadence it should be caught. Report the finding
    # either way: a state the code defines and no run has ever shown is a claim,
    # not a behaviour.
    if dc logs --no-log-prefix node0 node1 node2 2>/dev/null | grep -q 'regime=Halting'; then
      echo "   ✓ regime=Halting OBSERVED during the boundary vote round:"
      dc logs --no-log-prefix node0 node1 node2 2>/dev/null | grep 'regime=Halting' | head -4 | sed 's/^/       /'
    else
      echo "   (finding) regime=Halting was NOT observed even at a 5 s sampling cadence."
      echo "             Record it as not-observed, with the vote-round duration, rather than"
      echo "             asserting the transition. Halting is covered in-process; this run"
      echo "             does not evidence it."
    fi
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
    # …and its finality STOPS ADVANCING while the checkpointed branch carries on.
    #
    # WHY NOT `node3.final > H`. That was this drill's original check and it is
    # UNSOUND — it fired on 2026-07-27 against a net that was behaving exactly as
    # §4 describes. A node's `final=` advances when it finalizes ANYONE's
    # checkpoint, including the one every other node finalized: node3 reported
    # `final=24` with `tip=23`, i.e. it had tracked the UPGRADED branch's
    # checkpoint, not produced one of its own. One checkpoint finalized, not two.
    #
    # The condition this check actually guards is "did a SECOND, DIFFERENT
    # checkpoint finalize at some height". Until 2026-07-29 that was NOT expressible
    # from telemetry, because TELEMETRY carried no checkpoint identity — and a
    # stop-check that cannot express the condition it guards will eventually fire on
    # the condition it can express instead, which is precisely what happened.
    #
    # Issue #84 (lab PR #110) closed that: `fid` is the finalized checkpoint's
    # identity, so `halt_assert_no_conflicting_finality` now compares identities at a
    # shared height and dies on the real condition instead of a proxy for it. It
    # says so explicitly when the running image is too old to carry the field, since
    # a silent pass is the same defect arriving from the other direction.
    #
    # The freeze check below is KEPT, and is no longer a proxy for the above — it
    # tests a different §4 expectation: the un-upgraded node's finality FREEZES while
    # the checkpointed branch keeps finalizing. It needs two samples spanning at
    # least one finalization on the checkpointed branch, driven by the condition
    # rather than by a fixed sleep, so it also surfaces a stalled checkpointed
    # branch as its own distinct finding.
    halt_assert_old_branch_finality_frozen
    halt_assert_no_conflicting_finality
    # Non-fatal, and node3 is included on purpose: it is the un-upgraded miner, so a
    # signed-variant split against it is expected here rather than alarming.
    halt_report_signed_divergence node0 node1 node2 node3
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
    # The whole leading comment block, not a fixed line range: `sed -n '2,60p'` was
    # already cutting the help off mid-drill before this file grew a netem section,
    # so the usage text silently stopped documenting the newest subcommands.
    awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
    exit 2
    ;;
esac
