#!/usr/bin/env bash
# Lab #847 S6 — the sequencer-v0 box run: a local V6 rehearsal net, the real
# `qumbra-sequencer` end to end, measured. Coordinator-run, on the box only
# (never a laptop): an L1 proof is ≈ 31 GiB.
#
#   scripts/s6-box.sh RUN_DIR [--bin DIR] [--port-base N] [--count N] [--resume-from TAR]
#
# --resume-from TAR restores a RUN_DIR pulled from an earlier box (tar of the
# run dir, extracted into RUN_DIR's parent when RUN_DIR is empty) and goes on
# from its phase markers: the chain, the wallets, the queue and the seed
# state carry over, so maturity and finished phases are not paid again.
# Pid and lock files from the old box are dropped first.
#
# RUN_DIR holds everything the run writes and must lie OUTSIDE any git
# worktree (refused otherwise). Binaries (not built here):
#   cargo build --release -p qumbra-node -p qumbra-wallet -p qumbra-sequencer
#
# Phases, each idempotent (RUN_DIR/phase-<name>.done skips it on a rerun),
# logged with timestamps to RUN_DIR/box.log:
#
#   genesis   `qumbra-node genesis init --t2` (the V6 rehearsal genesis); the
#             rehearsal sequencer key file (`qumbra-sequencer rehearsal-key`,
#             0600 — the PUBLIC rehearsal seed, never read here); a user
#             wallet (`qumbra-wallet keygen`), whose miner-rkm the producer
#             mines to.
#   producer  one producer with all 21 committee keys, the operator listener,
#             75 s blocks, under time -v + a 1 s VmRSS sampler.
#   intake    `qumbra-sequencer intake` on loopback over RUN_DIR/queue.
#   fund-notes the user wallet sends the sequencer's L1 wallet ONE NOTE PER
#             BURN still to make (BURN + 1 QMB each), each mined before the
#             next — so no burn waits on another burn's change finalizing
#             (run 1 on 2026-10-03 measured ≈ 10 min of finality lag per burn
#             when every burn spent the last one's change).
#   seed      `seed --plan`, then `seed` under time -v + sampler: COUNT burns
#             (one L1 proof each, mined one after another) and COUNT claims
#             credited to the sequencer, handed to the intake. Rerun until
#             every deposit is claimed (a burn above the newest finalized
#             anchor is claimed by the next run).
#   claim1    the user wallet deposits and proves its claim (`deposit` +
#             `deposit claim`), POSTed to the intake — traffic.
#   pass1     the intake stops (`run` takes its queue lock); one pass under
#             time -v + sampler: 15 seed claims + 1 user claim = 16 C. Exit 0
#             = landed (the pass watches `/v1/wrapper`). The intake restarts.
#   claim2    a second user deposit + claim.
#   pass2     the restart drill: a pass (1 claim + 15 S fillers from the
#             sequencer's own notes) is KILLED (-9) once it has drafted —
#             after the proof, with the bundle in flight — then rerun. The
#             rerun must land it WITHOUT proving again (no `SEQ proving`
#             before `SEQ landed` in its log): the pending record and the
#             bytes in --out carry it.
#
# Locks: `intake` and `run` hold `queue/index.lock` and `run` also
# `seq-state.json.lock` — files created new and removed when the process
# exits cleanly. The intake installs no signal handler, so it is stopped with
# TERM; a TERM- or -9-killed process leaves its lock file behind, and this
# script removes it only after the holder's pid is confirmed gone (what the
# lock's own refusal tells an operator to do).
#
# Measures (all under RUN_DIR):
#   seed/seed-<n>.{time,rss,err}    one set per seed run: the max peak RSS
#                                   (the L1 proofs), the total wall, and each
#                                   burn's prove_secs go into the verdict
#   seq-out/bundle-{0,1}.json       per-member timings (member_i_S/C), bytes
#   pass1/run.{time,rss}            the claims-only pass: peak, wall
#   pass2/run-a.{time,rss}          the filler pass up to the kill
#   pass2/run-b.{time,rss}          the rerun: reconcile + land, no prove
#   producer/node.{time,rss}        the producer across the run
# The last line is one verdict.
set -euo pipefail

die() { log "FAIL: $*"; echo "S6 BOX VERDICT: FAIL — $*"; exit 1; }
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$RUN/box.log" >&2; }

[ $# -ge 1 ] || { sed -n '2,10p' "$0"; exit 2; }
RUN=$(mkdir -p "$1" && cd "$1" && pwd); shift
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/target/release"
PORT=39500
COUNT=15
RESUME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN=$(cd "$2" && pwd); shift 2 ;;
    --port-base) PORT=$2; shift 2 ;;
    --count) COUNT=$2; shift 2 ;;
    --resume-from) RESUME=$(cd "$(dirname "$2")" && pwd)/$(basename "$2"); shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
if [ -n "$RESUME" ]; then
  [ -r "$RESUME" ] || { echo "--resume-from $RESUME is not readable" >&2; exit 2; }
  if [ ! -e "$RUN/phase-genesis.done" ]; then
    top=$(tar -tf "$RESUME" | head -1 | cut -d/ -f1)
    [ "$top" = "$(basename "$RUN")" ] || { echo "$RESUME holds $top/, not $(basename "$RUN")/" >&2; exit 2; }
    tar -C "$(dirname "$RUN")" -xf "$RESUME" || { echo "extracting $RESUME failed" >&2; exit 2; }
    # The old box's processes are gone: their pid files and lock files are stale.
    find "$RUN" \( -name '*.pid' -o -name '*.timepid' -o -name 'index.lock' -o -name '*.json.lock' \) -type f -delete
  fi
fi
touch "$RUN/box.log"
if [ -n "$RESUME" ]; then
  # The configs written by the first box name absolute paths: the run dir
  # must be at the same path here (same user, same RUN_DIR).
  cfg_dir=$(sed -n 's/^data_dir = "\(.*\)\/producer\/data"$/\1/p' "$RUN/producer/node.toml" 2>/dev/null || true)
  [ -z "$cfg_dir" ] || [ "$cfg_dir" = "$RUN" ] || { echo "the restored configs name $cfg_dir, not $RUN — use RUN_DIR=$cfg_dir" >&2; exit 2; }
  log "resumed from $RESUME"
fi

# --- preflight ---------------------------------------------------------------------
if git -C "$RUN" rev-parse --show-toplevel >/dev/null 2>&1; then
  die "$RUN is inside a git worktree; put the run under ~/develop/qumbra/logs/"
fi
for b in qumbra-node qumbra-wallet qumbra-sequencer; do [ -x "$BIN/$b" ] || die "no $BIN/$b — build it first"; done
[ -x /usr/bin/time ] && /usr/bin/time -v true >/dev/null 2>&1 || die "/usr/bin/time -v (GNU time) is required"
[ -r /proc/self/status ] || die "/proc is required for the VmRSS sampler (run on the Linux box)"
command -v curl >/dev/null || die "curl is required"
command -v jq >/dev/null || die "jq is required (the manifests' timings)"
log "run dir $RUN, binaries $BIN, ports from $PORT, seed count $COUNT"

NODE="$BIN/qumbra-node"; WALLET="$BIN/qumbra-wallet"; SEQ="$BIN/qumbra-sequencer"
NET="$RUN/net"; GEN="$NET/genesis.qmb"; WDIR="$RUN/wallet"; KEY="$NET/sequencer.key"
QDIR="$RUN/queue"; STATE="$RUN/seq-state.json"; OUT="$RUN/seq-out"; SEED="$RUN/seed"
P_LISTEN=$((PORT)); P_DISC=$((PORT + 1)); P_TELE=$((PORT + 2)); P_OPER=$((PORT + 3)); P_METR=$((PORT + 4)); P_INT=$((PORT + 5))
DISC="http://127.0.0.1:$P_DISC"
L2_ID=1
BURN=50000000        # 0.5 QMB per seed burn (bessel)
USER_DEPOSIT=100000000

done_mark() { date -u +%Y-%m-%dT%H:%M:%SZ > "$RUN/phase-$1.done"; log "phase $1 done"; }
is_done() { [ -e "$RUN/phase-$1.done" ]; }

sample_rss() {
  local pid=$1 out=$2
  ( while kill -0 "$pid" 2>/dev/null; do
      awk -v t="$(date +%s)" '/^VmRSS/{print t, $2}' "/proc/$pid/status" 2>/dev/null || true
      sleep 1
    done ) >>"$out" &
}

start_measured() {
  local tag=$1; shift
  /usr/bin/time -v -o "$tag.time" "$@" >>"$tag.out" 2>>"$tag.err" &
  local tpid=$! cpid=""
  for _ in $(seq 1 50); do cpid=$(pgrep -P "$tpid" | head -1 || true); [ -n "$cpid" ] && break; sleep 0.1; done
  [ -n "$cpid" ] || return 0
  echo "$tpid" > "$tag.timepid"
  sample_rss "$cpid" "$tag.rss"
  echo "$cpid"
}

run_measured() {
  local tag=$1; shift
  /usr/bin/time -v -o "$tag.time" "$@" >>"$tag.out" 2>>"$tag.err" &
  local tpid=$! cpid=""
  for _ in $(seq 1 50); do cpid=$(pgrep -P "$tpid" | head -1 || true); [ -n "$cpid" ] && break; sleep 0.1; done
  [ -n "$cpid" ] && sample_rss "$cpid" "$tag.rss"
  local rc=0; wait "$tpid" || rc=$?
  return $rc
}

tip_of() { { grep -o 'TELEMETRY tip=[0-9]*' "$1" 2>/dev/null || true; } | tail -1 | cut -d= -f2; }
peak_kib() { { grep 'Maximum resident' "$1" 2>/dev/null || true; } | awk '{print $NF}'; }
wall_of() { { grep 'Elapsed (wall clock)' "$1" 2>/dev/null || true; } | awk '{print $NF}'; }
# GNU time's wall (h:mm:ss or m:ss.ss) in whole seconds; nothing if absent.
wall_s() { wall_of "$1" | awk -F: '{ s = 0; for (i = 1; i <= NF; i++) s = s * 60 + $i; printf "%d\n", s }'; }

LAST_WAIT=""; LAST_BEAT=0
wait_log() {
  local now; now=$(date +%s)
  if [ "$*" != "$LAST_WAIT" ] || [ $((now - LAST_BEAT)) -ge 600 ]; then
    log "$*"; LAST_WAIT="$*"; LAST_BEAT=$now
  fi
}

node_config() { # name listen disc tele metr oper mining(true|false) keys(yes|no)
  local name=$1 dir="$RUN/$1"
  mkdir -p "$dir"
  {
    echo "data_dir = \"$dir/data\""
    echo "listen_addr = \"127.0.0.1:$2\""
    echo "genesis_file = \"$GEN\""
    echo "expected_genesis_hash = \"$(cat "$NET/genesis.hash")\""
    echo "discovery_addr = \"127.0.0.1:$3\""
    echo "telemetry_addr = \"127.0.0.1:$4\""
    echo "metrics_addr = \"127.0.0.1:$5\""
    echo "operator_addr = \"127.0.0.1:$6\""
    echo "mining = $7"
    [ "$7" = true ] && echo "miner_rkm = \"$(cat "$WDIR/rkm")\""
    if [ "$8" = yes ]; then
      printf 'committee_key_paths = ['; for i in $(seq -w 0 20); do printf '"%s",' "$NET/keys/committee-$i.key"; done; echo ']'
    fi
  } > "$dir/node.toml"
  "$NODE" check --config "$dir/node.toml" >>"$dir/check.log" 2>&1 || die "$name: qumbra-node check refused its config (see $dir/check.log)"
}

start_producer() {
  local pid
  pid=$(start_measured "$RUN/producer/node" "$NODE" run --config "$RUN/producer/node.toml" --sample-interval-secs 10)
  [ -n "$pid" ] || die "the producer did not start (see $RUN/producer/node.err)"
  echo "$pid" > "$RUN/producer/node.pid"; date +%s > "$RUN/producer/node.started"
  log "producer up (pid $pid)"
}
producer_up() { local pid; pid=$(cat "$RUN/producer/node.pid" 2>/dev/null || true); [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; }

stop_pid_file() { # pidfile what signal
  local pid; pid=$(cat "$1" 2>/dev/null || true)
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 0
  # A process signalled in its first second may not have installed its
  # handler yet (box run 3 of F5-6): never stop one younger than 5 s.
  local started; started=$(cat "${1%.pid}.started" 2>/dev/null || echo 0)
  while [ $(( $(date +%s) - started )) -lt 5 ]; do sleep 1; done
  kill "-$3" "$pid"
  for _ in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  kill -0 "$pid" 2>/dev/null && die "$2 did not stop on SIG$3 within 120 s"
  log "stopped $2 (pid $pid, SIG$3)"
}

# The queue (and state) lock files a killed holder left: removed only when no
# intake or pass is alive.
clear_stale_locks() {
  intake_up && return 0
  [ -n "${PASS_PID:-}" ] && kill -0 "$PASS_PID" 2>/dev/null && return 0
  for l in "$QDIR/index.lock" "$STATE.lock"; do
    [ -e "$l" ] && { rm -f "$l"; log "removed the stale lock $l (its holder is gone)"; }
  done
  return 0
}
stop_intake() { stop_pid_file "$RUN/intake/intake.pid" intake TERM; clear_stale_locks; }

start_intake() {
  mkdir -p "$RUN/intake"
  clear_stale_locks
  "$SEQ" intake --genesis "$GEN" --queue "$QDIR" --listen "127.0.0.1:$P_INT" >>"$RUN/intake/intake.out" 2>>"$RUN/intake/intake.err" &
  echo $! > "$RUN/intake/intake.pid"; date +%s > "$RUN/intake/intake.started"
  local up=""
  for _ in $(seq 1 30); do curl -s -o /dev/null "http://127.0.0.1:$P_INT/v1/intake/00" && { up=1; break; }; sleep 1; done
  [ -n "$up" ] || die "the intake did not answer within 30 s (see $RUN/intake/intake.err)"
  log "intake up (pid $(cat "$RUN/intake/intake.pid"))"
}
intake_up() { local pid; pid=$(cat "$RUN/intake/intake.pid" 2>/dev/null || true); [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; }

# On any exit — a die included — nothing is left burning on the box: a pass
# in flight and the intake get TERM, the producer INT (its own handler
# flushes); the samplers end with their processes.
cleanup() {
  [ -n "${PASS_PID:-}" ] && kill -TERM "$PASS_PID" 2>/dev/null || true
  for f in "$RUN/intake/intake.pid:TERM" "$RUN/producer/node.pid:INT"; do
    local pid; pid=$(cat "${f%%:*}" 2>/dev/null || true)
    [ -n "$pid" ] && kill "-${f##*:}" "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

w() { "$WALLET" "$@" --net t2 --dir "$WDIR" --url "$DISC"; }

# A user deposit and its claim, POSTed to the intake; $1 = which (1, 2).
user_claim() {
  local k=$1 f="$RUN/user/claim-$1.claim" code
  mkdir -p "$RUN/user"
  if [ ! -e "$RUN/user/deposit-$k.done" ]; then
    until w deposit --node "$DISC" --scan-to "$(tip_of "$RUN/producer/node.out")" --amount "$USER_DEPOSIT" \
          --l2-id "$L2_ID" --genesis-hash "$(cat "$NET/genesis.hash")" >>"$RUN/user/deposit-$k.out" 2>>"$RUN/user/deposit-$k.err"; do
      producer_up || die "the producer exited"
      wait_log "user deposit $k not made yet: $(tail -1 "$RUN/user/deposit-$k.err")"; sleep 60
    done
    touch "$RUN/user/deposit-$k.done"; log "user deposit $k submitted"
  fi
  if [ ! -e "$f" ]; then
    until w deposit claim --node "$DISC" --scan-to "$(tip_of "$RUN/producer/node.out")" --l2-id "$L2_ID" \
          --genesis-hash "$(cat "$NET/genesis.hash")" --deposit $((k - 1)) --out "$f" >>"$RUN/user/claim-$k.out" 2>>"$RUN/user/claim-$k.err"; do
      producer_up || die "the producer exited"
      wait_log "user claim $k not provable yet: $(tail -1 "$RUN/user/claim-$k.err")"; sleep 60
    done
    log "user claim $k proved ($(wc -c < "$f") B)"
  fi
  code=$(curl -s -o "$RUN/user/post-$k.body" -w '%{http_code}' --data-binary "@$f" "http://127.0.0.1:$P_INT/v1/intake" || echo 000)
  case "$code" in 202|409) log "the intake took user claim $k ($code)" ;; *) die "the intake refused user claim $k: $code $(head -c 300 "$RUN/user/post-$k.body")" ;; esac
}

# One posting pass's command line (an array: /usr/bin/time execs it, so it
# cannot be a shell function).
PASS=("$SEQ" run --genesis "$GEN" --queue "$QDIR" --state "$STATE" --node "$DISC" --telemetry "127.0.0.1:$P_TELE"
  --operator "127.0.0.1:$P_OPER" --key "$KEY" --out "$OUT" --max-wait 10800 --poll 30)

# --- genesis -------------------------------------------------------------------------
if ! is_done genesis; then
  mkdir -p "$NET"
  [ -e "$GEN" ] || "$NODE" genesis init --t2 --out "$NET" > "$NET/init.log" 2>&1 || die "genesis init (see $NET/init.log)"
  { grep 'GENESIS HASH:' "$NET/init.log" || true; } | awk '{print $3}' > "$NET/genesis.hash"
  [ "$(wc -c < "$NET/genesis.hash")" -ge 64 ] || die "no GENESIS HASH line in $NET/init.log"
  [ -e "$KEY" ] || "$SEQ" rehearsal-key --genesis "$GEN" --out "$KEY" 2>>"$NET/init.log" || die "rehearsal-key (see $NET/init.log)"
  mkdir -p "$WDIR"
  [ -e "$WDIR/address" ] || {
    "$WALLET" keygen --dir "$WDIR" > "$WDIR/keygen.log" 2>&1 || die "wallet keygen"
    { grep -A1 'address \[0\]:' "$WDIR/keygen.log" || true; } | tail -1 | tr -d ' ' > "$WDIR/address"
  }
  "$WALLET" miner-rkm --dir "$WDIR" > "$WDIR/miner-rkm.out" 2>&1 || die "wallet miner-rkm"
  sed -n 's/.*miner_rkm = "\([0-9a-f]*\)".*/\1/p' "$WDIR/miner-rkm.out" > "$WDIR/rkm"
  [ "$(wc -c < "$WDIR/rkm")" -ge 64 ] || die "no miner_rkm from the wallet"
  log "genesis $(cat "$NET/genesis.hash"); the producer mines to the user wallet $(cat "$WDIR/rkm")"
  done_mark genesis
fi

# --- producer, intake -------------------------------------------------------------------
if ! is_done producer; then
  node_config producer "$P_LISTEN" "$P_DISC" "$P_TELE" "$P_METR" "$P_OPER" true yes
  done_mark producer
fi
producer_up || start_producer
intake_up || start_intake

# --- fund: the sequencer's L1 wallet ------------------------------------------------------
mkdir -p "$SEED"
seq_seed() { "$SEQ" seed --genesis "$GEN" --key "$KEY" --node "$DISC" --out "$SEED" --burn "$BURN" --count "$COUNT" --intake "127.0.0.1:$P_INT" "$@"; }
if ! is_done fund-notes; then
  seq_seed --plan > "$SEED/plan-0.out" 2>"$SEED/plan-0.err" || true
  SEQ_ADDR=$({ grep -o 'L1 wallet address [^ ]*' "$SEED/plan-0.out" || true; } | awk '{print $4}')
  [ -n "$SEQ_ADDR" ] || die "seed --plan named no L1 wallet address (see $SEED/plan-0.*)"
  echo "$SEQ_ADDR" > "$SEED/l1-address"
  # How many burns are still to make (the plan's own count; a resumed run
  # already holds some deposits), less the notes this phase already sent.
  TO_BURN=$({ grep -o '[0-9]* burn(s) of' "$SEED/plan-0.out" || true; } | head -1 | awk '{print $1}')
  [ -n "$TO_BURN" ] || die "seed --plan named no burn count (see $SEED/plan-0.out)"
  SENT=$(cat "$SEED/fund-notes.sent" 2>/dev/null || echo 0)
  NOTE=$((BURN + 100000000))   # one burn, its posted fee, and room
  log "funding $TO_BURN note(s) of $NOTE bessel to $SEQ_ADDR ($SENT already sent)"
  while [ "$SENT" -lt "$TO_BURN" ]; do
    t0=$(tip_of "$RUN/producer/node.out")
    until w send --node "$DISC" --scan-to "$(tip_of "$RUN/producer/node.out")" --to "$SEQ_ADDR" --amount "$NOTE" \
          >>"$SEED/fund.out" 2>>"$SEED/fund.err"; do
      producer_up || die "the producer exited"
      wait_log "fund note $((SENT + 1)) not possible yet (tip $(tip_of "$RUN/producer/node.out")): $(tail -1 "$SEED/fund.err")"; sleep 60
    done
    SENT=$((SENT + 1)); echo "$SENT" > "$SEED/fund-notes.sent"
    # Mined before the next send: otherwise the next selection reads the same
    # unmined input. Two blocks past the tip it was built at.
    until t=$(tip_of "$RUN/producer/node.out"); [ -n "$t" ] && [ "$t" -ge $(( ${t0:-0} + 2 )) ]; do
      producer_up || die "the producer exited"; sleep 15
    done
    log "fund note $SENT of $TO_BURN sent (tip $(tip_of "$RUN/producer/node.out"))"
  done
  done_mark fund-notes
fi

# --- seed ------------------------------------------------------------------------------------
if ! is_done seed; then
  # Bounded by wall time, not run count (run 1 hit a 30-run cap after three
  # burns): four hours from the phase's first start, kept across reruns.
  [ -e "$SEED/seed.started" ] || date +%s > "$SEED/seed.started"
  SEED_DEADLINE=$(( $(cat "$SEED/seed.started") + 4 * 3600 ))
  for i in $(seq 1 1000); do
    [ -e "$SEED/seed-$i.time" ] && continue   # a rerun of this phase keeps every earlier run's files
    seq_seed --plan > "$SEED/plan-$i.out" 2>"$SEED/plan-$i.err" || true
    if run_measured "$SEED/seed-$i" "$SEQ" seed --genesis "$GEN" --key "$KEY" --node "$DISC" --out "$SEED" --burn "$BURN" \
         --count "$COUNT" --intake "127.0.0.1:$P_INT"; then
      break
    fi
    producer_up || die "the producer exited"
    wait_log "seed run $i not done: $(tail -1 "$SEED/seed-$i.err")"; sleep 60
    [ "$(date +%s)" -lt "$SEED_DEADLINE" ] || die "seed did not finish within 4 h of its first start (see $SEED/seed-*.err)"
  done
  n=$(find "$SEED/claims" -maxdepth 1 -name '*.claim.taken' 2>/dev/null | wc -l | tr -d ' ')
  [ "$n" -ge "$COUNT" ] || die "the intake holds $n seed claims, not $COUNT"
  log "seed: $n claims taken"
  done_mark seed
fi

# --- traffic, pass 1 ------------------------------------------------------------------------
if ! is_done pass1; then
  user_claim 1
  stop_intake
  mkdir -p "$RUN/pass1"
  for f in run.out run.err run.rss run.time; do : > "$RUN/pass1/$f"; done   # this attempt's evidence only
  clear_stale_locks
  run_measured "$RUN/pass1/run" "${PASS[@]}" || die "pass 1 did not drain (exit $?; see $RUN/pass1/run.err)"
  grep -q 'SEQ landed bundle' "$RUN/pass1/run.err" || die "pass 1 landed nothing"
  log "pass 1 landed: $(grep 'SEQ landed bundle' "$RUN/pass1/run.err" | tail -1); peak $(peak_kib "$RUN/pass1/run.time") KiB, wall $(wall_of "$RUN/pass1/run.time")"
  start_intake
  done_mark pass1
fi
intake_up || start_intake

# --- pass 2: fillers, and the restart drill ---------------------------------------------------
if ! is_done pass2; then
  user_claim 2
  stop_intake
  mkdir -p "$RUN/pass2"
  if [ ! -e "$RUN/pass2/killed" ]; then
    for f in run-a.out run-a.err run-a.rss run-a.time; do : > "$RUN/pass2/$f"; done
    clear_stale_locks
    /usr/bin/time -v -o "$RUN/pass2/run-a.time" "${PASS[@]}" >>"$RUN/pass2/run-a.out" 2>>"$RUN/pass2/run-a.err" &
    tpid=$!
    cpid=""; for _ in $(seq 1 50); do cpid=$(pgrep -P "$tpid" | head -1 || true); [ -n "$cpid" ] && break; sleep 0.1; done
    [ -n "$cpid" ] || die "pass 2 did not start"
    PASS_PID=$cpid
    sample_rss "$cpid" "$RUN/pass2/run-a.rss"
    until grep -q 'SEQ drafted bundle' "$RUN/pass2/run-a.err" 2>/dev/null; do
      kill -0 "$cpid" 2>/dev/null || die "pass 2 ended before drafting (see $RUN/pass2/run-a.err)"
      sleep 5
    done
    kill -9 "$cpid" || die "pass 2 (run-a) exited before the kill — see $RUN/pass2/run-a.err"
    wait "$tpid" 2>/dev/null || true
    PASS_PID=""
    date -u +%Y-%m-%dT%H:%M:%SZ > "$RUN/pass2/killed"
    log "pass 2 KILLED (-9) after: $(grep 'SEQ drafted bundle' "$RUN/pass2/run-a.err" | tail -1)"
  fi
  for f in run-b.out run-b.err run-b.rss run-b.time; do : > "$RUN/pass2/$f"; done
  clear_stale_locks   # the -9'd pass left queue/index.lock and the state lock
  run_measured "$RUN/pass2/run-b" "${PASS[@]}" || die "the rerun did not drain (see $RUN/pass2/run-b.err)"
  grep -q 'SEQ landed bundle' "$RUN/pass2/run-b.err" || die "the rerun landed nothing"
  before_land=$(sed -n '1,/SEQ landed bundle/p' "$RUN/pass2/run-b.err" | { grep -c 'SEQ proving' || true; })
  [ "$before_land" = 0 ] || die "the rerun proved again ($before_land 'SEQ proving' lines before it landed) — the pending record did not carry the bundle"
  log "pass 2 rerun landed without proving: $(grep 'SEQ landed bundle' "$RUN/pass2/run-b.err" | tail -1)"
  start_intake
  done_mark pass2
fi

stop_intake
stop_pid_file "$RUN/producer/node.pid" producer INT
sleep 2   # GNU time writes node.time as the producer exits
# The filler pass's manifest: the highest-numbered bundle (pass 2's), by number.
M2=$(find "$OUT" -maxdepth 1 -name 'bundle-*.json' | sort -V | tail -1)
[ -n "$M2" ] || die "no bundle manifest under $OUT"
fillers=$(jq '[.members[] | select(.filler == true)] | length' "$M2")
n_s=$(jq '[.timings_seconds[] | select(.step | test("_S$"))] | length' "$M2")
[ "$fillers" = 15 ] && [ "$n_s" = 15 ] || die "$M2 has $fillers filler member(s) and $n_s S proving step(s), not 15 and 15"
s_times=$(jq -r '[.timings_seconds[] | select(.step | test("_S$")) | .seconds] | "min \(min | . * 100 | round / 100) max \(max | . * 100 | round / 100) mean \(add / length | . * 100 | round / 100)"' "$M2")
seed_peak=$(for f in "$SEED"/seed-*.time; do peak_kib "$f"; done | sort -n | tail -1)
seed_wall=$(for f in "$SEED"/seed-*.time; do wall_s "$f"; done | awk '{ s += $1 } END { print s + 0 }')
burn_secs=$(cat "$SEED"/seed-*.err 2>/dev/null | { grep -o 'prove_secs: [0-9.]*' || true; } | awk '{print $2}' | paste -sd' ' -)
log "measurements: $SEED/seed-*.time, $RUN/pass1/run.time, $RUN/pass2/run-{a,b}.time, $M2, producer/node.time"
echo "S6 BOX VERDICT: PASS — seed: $COUNT claims taken, $(ls "$SEED"/seed-*.time | wc -l | tr -d ' ') run(s), max peak $seed_peak KiB, total wall ${seed_wall} s, burn prove_secs [${burn_secs}]; pass 1 (16 C): peak $(peak_kib "$RUN/pass1/run.time") KiB, wall $(wall_s "$RUN/pass1/run.time") s; pass 2 (1 C + 15 S): killed -9 after drafting (run-a peak $(peak_kib "$RUN/pass2/run-a.time") KiB), rerun landed it with no re-prove in $(wall_s "$RUN/pass2/run-b.time") s; $fillers filler members, S seconds $s_times ($M2); producer peak $(peak_kib "$RUN/producer/node.time") KiB over $(wall_s "$RUN/producer/node.time") s"
