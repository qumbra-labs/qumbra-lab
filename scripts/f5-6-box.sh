#!/usr/bin/env bash
# Lab #785 F5-6 (2) — the box run: a local V6 rehearsal net carrying two real
# L2 bundles, measured. Coordinator-run, on the box only (never a laptop): the
# member proves are 7–31 GiB each.
#
#   scripts/f5-6-box.sh RUN_DIR [--bin DIR] [--resume-from TAR] [--port-base N]
#
# RUN_DIR holds everything the run writes (configs, datadirs, logs, the f5box
# state and bundles, the measurements) and must lie OUTSIDE any git worktree —
# the script refuses one inside (the state file carries the rehearsal seed and
# nothing here belongs in a repository). Default home: ~/develop/qumbra/logs/.
#
# Binaries (not built here):  cargo build --release -p qumbra-node -p qumbra-wallet -p qlab-bench
# --bin DIR defaults to this checkout's target/release.
#
# Phases, in order; each is idempotent (a `RUN_DIR/phase-<name>.done` marker
# skips it on a rerun) and logged with timestamps to RUN_DIR/box.log:
#
#   genesis    `qumbra-node genesis init --t2` (the V6 rehearsal genesis, 21
#              rehearsal committee key files — passed by path, never read here),
#              the wallet (`keygen`, its `miner-rkm` = the exit recipient), the
#              burn rkm (`qlab-bench f5box --burn-rkm`).
#   producer   the one producer: all 21 committee keys, mining to rkm_burn(1),
#              a loopback operator listener; under /usr/bin/time -v with a 1 s
#              VmRSS sampler. 75 s blocks (the frozen pace, ruled (a)).
#   ready      `f5box --check` every 60 s until the deposit plans (16 burns
#              matured and under a record: tip ≳ 161, ≈ 3.4 h), then the
#              checkpoint: the producer stops, its datadir is tarred to
#              RUN_DIR/datadir-pre-deposit.tar (reusable: --resume-from), and
#              it restarts.
#   deposit    `f5box` builds bundle 0 (sixteen claims) under time -v + sampler;
#              it is posted to `POST /v1/bundle` until admitted and watched until
#              it lands.
#   mix        `f5box --next --check` until the mix plans, then `f5box --next`
#              builds bundle 1 (8 P / 3 S / 1 R / 4 C, the first P paying the
#              exit to the wallet), posted and watched the same way (the node's
#              48-block spacing answers 422 until it passes — retried).
#   peers      three FRESH keyless peers start together from genesis and catch
#              up to the producer's tip (through both bundle blocks, verifying
#              each bundle's proofs); each under time -v + sampler.
#   exit       the wallet scans until its exit is visible, sends a proven spend
#              of it, and the spend is watched until the scan reports it spent
#              (a V6 node mines it once a finality record covers its anchor).
#
# The last line is one verdict with the manifest paths. Progress lines stay in
# box.log; nothing here needs a terminal. The box's auto-shutdown should be set
# beyond the run (ruled +480 min).
#
# How "landed" is read: no node route or log line states a bundle's inclusion
# (a named gap for the sequencer-v0 milestone). The script re-posts the same
# bytes: 409 = still pooled; 422 naming Spacing / Thread / Prev = the chain's
# surface has moved past it (landed); every answer is logged.
set -euo pipefail

die() { log "FAIL: $*"; echo "F5-6 BOX VERDICT: FAIL — $*"; exit 1; }
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$RUN/box.log" >&2; }

[ $# -ge 1 ] || { sed -n '2,12p' "$0"; exit 2; }
RUN=$(mkdir -p "$1" && cd "$1" && pwd); shift
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/target/release"
RESUME=""
PORT=39400
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN=$(cd "$2" && pwd); shift 2 ;;
    --resume-from) RESUME=$(cd "$(dirname "$2")" && pwd)/$(basename "$2"); shift 2 ;;
    --port-base) PORT=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
touch "$RUN/box.log"

# --- preflight -----------------------------------------------------------------
if git -C "$RUN" rev-parse --show-toplevel >/dev/null 2>&1; then
  die "$RUN is inside a git worktree ($(git -C "$RUN" rev-parse --show-toplevel)); put the run under ~/develop/qumbra/logs/"
fi
for b in qumbra-node qumbra-wallet qlab-bench; do [ -x "$BIN/$b" ] || die "no $BIN/$b — build it first"; done
[ -x /usr/bin/time ] && /usr/bin/time -v true >/dev/null 2>&1 || die "/usr/bin/time -v (GNU time) is required"
[ -r /proc/self/status ] || die "/proc is required for the VmRSS sampler (run on the Linux box)"
command -v curl >/dev/null || die "curl is required"
[ -z "$RESUME" ] || [ -r "$RESUME" ] || die "--resume-from $RESUME is not readable"
log "run dir $RUN, binaries $BIN, ports from $PORT${RESUME:+, resuming from $RESUME}"

NODE="$BIN/qumbra-node"; WALLET="$BIN/qumbra-wallet"; BENCH="$BIN/qlab-bench"
NET="$RUN/net"; GEN="$NET/genesis.qmb"; WDIR="$RUN/wallet"; F5="$RUN/f5box"; STATE="$F5/state.json"
P_LISTEN=$((PORT)); P_DISC=$((PORT + 1)); P_TELE=$((PORT + 2)); P_OPER=$((PORT + 3)); P_METR=$((PORT + 4))
DISC="http://127.0.0.1:$P_DISC"
EXIT_V=100000000   # 1 QMB in bessel, f5box's default made explicit

done_mark() { date -u +%Y-%m-%dT%H:%M:%SZ > "$RUN/phase-$1.done"; log "phase $1 done"; }
is_done() { [ -e "$RUN/phase-$1.done" ]; }

# The VmRSS sampler: one line per second, "epoch_s rss_kib", until PID exits.
sample_rss() {
  local pid=$1 out=$2
  ( while kill -0 "$pid" 2>/dev/null; do
      awk -v t="$(date +%s)" '/^VmRSS/{print t, $2}' "/proc/$pid/status" 2>/dev/null || true
      sleep 1
    done ) >>"$out" &
}

# Run "$@" under /usr/bin/time -v in the background, logging to $1.{out,err,time,rss};
# echoes the measured process's pid (time's child).
start_measured() {
  local tag=$1; shift
  /usr/bin/time -v -o "$tag.time" "$@" >>"$tag.out" 2>>"$tag.err" &
  local tpid=$! cpid=""
  for _ in $(seq 1 50); do cpid=$(pgrep -P "$tpid" | head -1 || true); [ -n "$cpid" ] && break; sleep 0.1; done
  [ -n "$cpid" ] || return 0   # the caller refuses an empty pid (a die here would end only this subshell)
  echo "$tpid" > "$tag.timepid"
  sample_rss "$cpid" "$tag.rss"
  echo "$cpid"
}

# Run "$@" in the foreground under time -v + sampler; returns its exit code.
run_measured() {
  local tag=$1; shift
  /usr/bin/time -v -o "$tag.time" "$@" >>"$tag.out" 2>>"$tag.err" &
  local tpid=$! cpid=""
  for _ in $(seq 1 50); do cpid=$(pgrep -P "$tpid" | head -1 || true); [ -n "$cpid" ] && break; sleep 0.1; done
  [ -n "$cpid" ] && sample_rss "$cpid" "$tag.rss"
  local rc=0; wait "$tpid" || rc=$?
  return $rc
}

tip_of() { grep -o 'TELEMETRY tip=[0-9]*' "$1" 2>/dev/null | tail -1 | cut -d= -f2; }

node_config() { # name listen disc tele metr oper mining(true|false) keys(yes|no) dial
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
    [ "$6" = - ] || echo "operator_addr = \"127.0.0.1:$6\""
    echo "mining = $7"
    [ "$7" = true ] && echo "miner_rkm = \"$(cat "$NET/burn.rkm")\""
    if [ "$8" = yes ]; then
      printf 'committee_key_paths = ['; for i in $(seq -w 0 20); do printf '"%s",' "$NET/keys/committee-$i.key"; done; echo ']'
    fi
    [ "$9" = - ] || echo "dial_peers = [\"127.0.0.1:$9\"]"
  } > "$dir/node.toml"
  "$NODE" check --config "$dir/node.toml" >>"$dir/check.log" 2>&1 || die "$name: qumbra-node check refused its config (see $dir/check.log)"
}

start_producer() {
  local pid
  pid=$(start_measured "$RUN/producer/node" "$NODE" run --config "$RUN/producer/node.toml" --sample-interval-secs 10)
  [ -n "$pid" ] || die "the producer did not start (see $RUN/producer/node.err)"
  echo "$pid" > "$RUN/producer/node.pid"
  log "producer up (pid $pid)"
}

stop_node() { # dir
  local pid; pid=$(cat "$1/node.pid" 2>/dev/null || true)
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 0
  kill -INT "$pid"
  for _ in $(seq 1 120); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  kill -0 "$pid" 2>/dev/null && die "$1: did not stop on SIGINT within 120 s"
  log "stopped $(basename "$1") (pid $pid)"
}

producer_up() { local pid; pid=$(cat "$RUN/producer/node.pid" 2>/dev/null || true); [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; }

f5box() { "$BENCH" f5box --genesis "$GEN" --chain "$DISC" --state "$STATE" --out "$F5" "$@"; }

# POST bundle-N until admitted (bounded: 120 × 60 s), then re-post until the
# rule says the chain moved past it (landed; bounded the same). Every answer logged.
post_and_land() {
  local n=$1 file="$F5/bundle-$1.bin" code body
  [ -r "$file" ] || die "no $file"
  for i in $(seq 1 120); do
    code=$(curl -s -o "$F5/post-$n.body" -w '%{http_code}' --data-binary "@$file" "http://127.0.0.1:$P_OPER/v1/bundle" || echo 000)
    body=$(head -c 300 "$F5/post-$n.body" 2>/dev/null || true)
    log "bundle $n post $i: $code $body (tip $(tip_of "$RUN/producer/node.out"))"
    case "$code" in
      202) break ;;
      409) log "bundle $n: the slot is held — treating as admitted (a pooled earlier post)"; break ;;
      400) die "bundle $n refused on its bytes: $body" ;;
      *) sleep 60 ;;
    esac
    [ "$i" = 120 ] && die "bundle $n not admitted after 120 attempts"
  done
  for i in $(seq 1 120); do
    sleep 60
    code=$(curl -s -o "$F5/land-$n.body" -w '%{http_code}' --data-binary "@$file" "http://127.0.0.1:$P_OPER/v1/bundle" || echo 000)
    body=$(head -c 300 "$F5/land-$n.body" 2>/dev/null || true)
    log "bundle $n landed? $i: $code $body (tip $(tip_of "$RUN/producer/node.out"))"
    case "$code" in
      422) if grep -qE 'Spacing|Thread|Prev' "$F5/land-$n.body"; then
             echo "$(tip_of "$RUN/producer/node.out") $body" > "$F5/landed-$n"; log "bundle $n LANDED"; return 0
           fi ;;
      202) log "bundle $n was re-admitted: it had left the pool without landing; watching again" ;;
    esac
  done
  die "bundle $n not seen landed after 120 checks"
}

# --- genesis ---------------------------------------------------------------------
if ! is_done genesis; then
  mkdir -p "$NET"
  [ -e "$GEN" ] || "$NODE" genesis init --t2 --out "$NET" > "$NET/init.log" 2>&1 || die "genesis init (see $NET/init.log)"
  grep 'GENESIS HASH:' "$NET/init.log" | awk '{print $3}' > "$NET/genesis.hash"
  [ "$(wc -c < "$NET/genesis.hash")" -ge 64 ] || die "no GENESIS HASH line in $NET/init.log"
  "$BENCH" f5box --burn-rkm --genesis "$GEN" > "$NET/burn.rkm" || die "f5box --burn-rkm"
  mkdir -p "$WDIR"
  [ -e "$WDIR/address" ] || {
    "$WALLET" keygen --dir "$WDIR" > "$WDIR/keygen.log" 2>&1 || die "wallet keygen"
    grep -A1 'address \[0\]:' "$WDIR/keygen.log" | tail -1 | tr -d ' ' > "$WDIR/address"
  }
  "$WALLET" miner-rkm --dir "$WDIR" | sed -n 's/.*miner_rkm = "\([0-9a-f]*\)".*/\1/p' > "$WDIR/rkm"
  [ "$(wc -c < "$WDIR/rkm")" -ge 64 ] || die "no miner_rkm from the wallet"
  log "genesis $(cat "$NET/genesis.hash"); burn rkm $(cat "$NET/burn.rkm"); exit to wallet rkm $(cat "$WDIR/rkm")"
  done_mark genesis
fi

# --- producer --------------------------------------------------------------------
if ! is_done producer; then
  node_config producer "$P_LISTEN" "$P_DISC" "$P_TELE" "$P_METR" "$P_OPER" true yes -
  if [ -n "$RESUME" ] && [ ! -e "$RUN/producer/data" ]; then
    tar -C "$RUN/producer" -xf "$RESUME" || die "extracting $RESUME"
    log "producer datadir restored from $RESUME"
  fi
  done_mark producer
fi
producer_up || start_producer

mkdir -p "$F5"

# --- ready: the deposit plans; the checkpoint ------------------------------------
if ! is_done ready; then
  until f5box --seed box --check > "$F5/check-0.json" 2>"$F5/check-0.err"; do
    producer_up || die "the producer exited (see $RUN/producer/node.err)"
    log "deposit not plannable yet (tip $(tip_of "$RUN/producer/node.out")): $(tail -1 "$F5/check-0.err")"
    sleep 60
  done
  log "the deposit plans at tip $(tip_of "$RUN/producer/node.out")"
  if [ -z "$RESUME" ]; then
    stop_node "$RUN/producer"
    tar -C "$RUN/producer" -cf "$RUN/datadir-pre-deposit.tar" data || die "tarring the datadir"
    log "checkpoint $RUN/datadir-pre-deposit.tar ($(wc -c < "$RUN/datadir-pre-deposit.tar") B)"
    start_producer
  fi
  done_mark ready
fi

# --- deposit: bundle 0 -----------------------------------------------------------
if ! is_done deposit; then
  if [ ! -e "$F5/bundle-0.bin" ]; then
    log "building the deposit (16 claim proves + W + deposit-sum)"
    run_measured "$F5/build-0" "$BENCH" f5box --genesis "$GEN" --chain "$DISC" --state "$STATE" --out "$F5" --seed box \
      || die "f5box (deposit) — see $F5/build-0.err and $F5/manifest-0.json"
  fi
  post_and_land 0
  done_mark deposit
fi

# --- mix: bundle 1 ---------------------------------------------------------------
if ! is_done mix; then
  if [ ! -e "$F5/bundle-1.bin" ]; then
    until f5box --next --exit-rkm "$(cat "$WDIR/rkm")" --exit-v "$EXIT_V" --check > "$F5/check-1.json" 2>"$F5/check-1.err"; do
      producer_up || die "the producer exited"
      log "the mix does not plan yet (tip $(tip_of "$RUN/producer/node.out")): $(tail -1 "$F5/check-1.err")"
      sleep 60
    done
    log "building the mix (8 P / 3 S / 1 R / 4 C + W + deposit-sum)"
    run_measured "$F5/build-1" "$BENCH" f5box --next --genesis "$GEN" --chain "$DISC" --state "$STATE" --out "$F5" \
      --exit-rkm "$(cat "$WDIR/rkm")" --exit-v "$EXIT_V" || die "f5box (mix) — see $F5/build-1.err and $F5/manifest-1.json"
  fi
  post_and_land 1
  done_mark mix
fi

# --- peers: three fresh, cold, together ------------------------------------------
if ! is_done peers; then
  target=$(tip_of "$RUN/producer/node.out")
  log "three fresh peers catch up to tip $target"
  for k in 1 2 3; do
    base=$((PORT + 10 * k))
    rm -rf "$RUN/peer$k/data"
    node_config "peer$k" "$base" $((base + 1)) $((base + 2)) $((base + 3)) - false no "$P_LISTEN"
  done
  start_s=$(date +%s)
  for k in 1 2 3; do
    pid=$(start_measured "$RUN/peer$k/node" "$NODE" run --config "$RUN/peer$k/node.toml" --sample-interval-secs 5)
    [ -n "$pid" ] || die "peer$k did not start (see $RUN/peer$k/node.err)"
    echo "$pid" > "$RUN/peer$k/node.pid"
  done
  for k in 1 2 3; do
    for _ in $(seq 1 720); do
      t=$(tip_of "$RUN/peer$k/node.out"); [ -n "$t" ] && [ "$t" -ge "$target" ] && break
      kill -0 "$(cat "$RUN/peer$k/node.pid")" 2>/dev/null || die "peer$k exited (see $RUN/peer$k/node.err)"
      sleep 5
    done
    t=$(tip_of "$RUN/peer$k/node.out"); [ -n "$t" ] && [ "$t" -ge "$target" ] || die "peer$k did not reach $target in an hour"
    echo "$(( $(date +%s) - start_s ))" > "$RUN/peer$k/catchup.seconds"
    log "peer$k reached $t in $(cat "$RUN/peer$k/catchup.seconds") s"
  done
  for k in 1 2 3; do stop_node "$RUN/peer$k"; done
  done_mark peers
fi

# --- exit: the wallet's proven spend of its exit note ----------------------------
scan() { "$WALLET" scan --net t2 --dir "$WDIR" --url "$DISC" --to "$(tip_of "$RUN/producer/node.out")" > "$WDIR/scan.txt" 2>&1; }
if ! is_done exit; then
  for i in $(seq 1 60); do
    scan || true
    grep -q 'exits paid: *[1-9]' "$WDIR/scan.txt" && break
    log "the exit is not visible yet ($i): $(grep -m1 'exits' "$WDIR/scan.txt" || echo 'no exits line')"
    sleep 60
  done
  grep -q 'exits paid: *[1-9]' "$WDIR/scan.txt" || die "the wallet never saw its exit (see $WDIR/scan.txt)"
  if [ ! -e "$WDIR/send.done" ]; then
    run_measured "$WDIR/send" "$WALLET" send --net t2 --dir "$WDIR" --url "$DISC" --node "$DISC" \
      --scan-to "$(tip_of "$RUN/producer/node.out")" --to "$(cat "$WDIR/address")" --amount $((EXIT_V / 2)) \
      || die "wallet send (see $WDIR/send.err)"
    touch "$WDIR/send.done"
    log "spend submitted: $(grep -m1 -E 'accepted|duplicate' "$WDIR/send.out" || tail -1 "$WDIR/send.out")"
  fi
  for i in $(seq 1 60); do
    scan || true
    grep -q 'already spent' "$WDIR/scan.txt" && break
    log "the exit spend has not landed yet ($i)"
    sleep 60
  done
  grep -q 'already spent' "$WDIR/scan.txt" || die "the exit spend never landed (see $WDIR/scan.txt)"
  done_mark exit
fi

stop_node "$RUN/producer"
log "measurements: $RUN/*/node.time, *.rss, $F5/build-*.time, $F5/manifest-*.json, peer*/catchup.seconds"
echo "F5-6 BOX VERDICT: PASS — deposit and mix landed ($(cut -d' ' -f1 "$F5/landed-0"), $(cut -d' ' -f1 "$F5/landed-1")), 3/3 peers caught up ($(cat "$RUN"/peer*/catchup.seconds | paste -sd/ -) s), exit spent; manifests $F5/manifest-0.json $F5/manifest-1.json"
