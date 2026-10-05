#!/usr/bin/env bash
# Lab #896 H (QH3) — the Candidate A box rehearsal: a local Annulet net on the
# rehearsal genesis (`devnet_v2_rehearsal`: format 33, one-second slots, an
# empty block every slot), the real binaries end to end. Coordinator-run, on
# the box only (never a laptop): a v2 S proof is ≈ 29 GiB, and the faucet
# and the wallets prove one at a time.
#
#   scripts/annulet-v2-rehearsal.sh RUN_DIR [--bin DIR] [--port-base N]
#
# RUN_DIR holds everything the run writes and must lie OUTSIDE any git
# worktree (refused otherwise). Binaries (not built here):
#   cargo build --release -p qumbra-node -p qumbra-wallet -p qumbra-faucet
#
# One process tree: a sequencer, a follower (the wallets' endpoint) and the
# faucet (its own keyless follower in process, `--fresh-journal` on its first
# start only). Wallets: A (the sender), B (the recipient), A2 and A3 (fresh
# dirs restored from A's mnemonic). The mnemonic goes from `backup --reveal`
# straight into `restore` through a pipe: it is never written or printed.
#
# Steps, each ending in one `STEP n PASS|FAIL` line (box.log and stdout):
#
#   1  keygen → migrate (journal at generation 0) → address --candidate-a →
#      two faucet grants → verified scan → a wallet-built, signed, really
#      proved S from A to B's v2 address through the follower's POST /v1/tx →
#      both balances read back.
#   2  A: migrate --open-next → generation 1 active, generation 0 waits (its
#      gate printed); two grants to A's generation-1 address and a send from
#      generation 1, so generation 1 has landed leaves.
#   3  restore: A2 from the same mnemonic → migrate: no generation resumed —
#      0 and 1 wait, 2 opens — and A2's journal positions for 0 and 1 equal
#      A's (the floor read back from the landed authorization sections). A is
#      retired (its dir renamed) so no two journals sign for one seed.
#   5  A2 sends to B's version-1 address: refused by name, nothing proved.
#   4  wait out A2's gates (≈ 20 min at one block a second) → migrate sweeps
#      generations 0 and 1 into 2 (re-run while it reports fee notes left) →
#      balances; then A3, restored again, migrates without sweeping and its
#      positions for 0, 1 and 2 equal A2's (landed_next after the sweeps).
#
# (5 runs before 4: it is the cheap refusal, and 4 is mostly a wait.)
#
# Measures: every proving wallet command and the faucet run under
# /usr/bin/time -v; RUN_DIR/<who>/<verb>-<n>.{time,out,err}. The last line
# is `REHEARSAL-DONE` after five PASS lines, or a FAIL verdict.
set -euo pipefail

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$RUN/box.log" >&2; }
die() { log "FAIL: $*"; echo "REHEARSAL VERDICT: FAIL — $*"; exit 1; }
pass() { log "STEP $1 PASS — $2"; echo "STEP $1 PASS — $2"; }
fail() { log "STEP $1 FAIL — $2"; echo "STEP $1 FAIL — $2"; die "step $1"; }

[ $# -ge 1 ] || { sed -n '2,9p' "$0"; exit 2; }
RUN=$(mkdir -p "$1" && cd "$1" && pwd); shift
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/target/release"
PORT=39700
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) BIN=$(cd "$2" && pwd); shift 2 ;;
    --port-base) PORT=$2; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
touch "$RUN/box.log"

# The rehearsal genesis's pinned hash (lab #896 H, `DEVNET_V2_REHEARSAL_GENESIS_HASH`):
# a binary that mints anything else is the wrong binary.
REHEARSAL_HASH=e21a7b089927dbede8171744675830bd60f8f3b854617421a9fcf8e4728fee97

# --- preflight ---------------------------------------------------------------------
if git -C "$RUN" rev-parse --show-toplevel >/dev/null 2>&1; then
  die "$RUN is inside a git worktree; put the run under ~/develop/qumbra/logs/"
fi
for b in qumbra-node qumbra-wallet qumbra-faucet; do [ -x "$BIN/$b" ] || die "no $BIN/$b — build it first"; done
[ -x /usr/bin/time ] && /usr/bin/time -v true >/dev/null 2>&1 || die "/usr/bin/time -v (GNU time) is required"
command -v curl >/dev/null || die "curl is required"
command -v od >/dev/null || die "od is required"
for f in "$RUN"/* "$RUN"/.[!.]*; do
  [ -e "$f" ] && [ "$f" != "$RUN/box.log" ] && die "$RUN is not empty: every rehearsal starts from a fresh run dir"
done
log "run dir $RUN, binaries $BIN, ports from $PORT"

NODE="$BIN/qumbra-node"; WALLET="$BIN/qumbra-wallet"; FAUCET="$BIN/qumbra-faucet"
NET="$RUN/net"
P_SEQ=$PORT; P_SEQ_DISC=$((PORT + 1)); P_FOL=$((PORT + 2)); P_FOL_DISC=$((PORT + 3)); P_FAU_NODE=$((PORT + 4)); P_FAUCET=$((PORT + 5))
DISC="http://127.0.0.1:$P_FOL_DISC"
FAUCET_URL="http://127.0.0.1:$P_FAUCET"
FAR=999999999   # --scan-to past any tip: the verified walk ends at the served tip

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill -INT "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

# The follower's own word on its tip: `GET /v1/registry/root` = version byte, u64 LE height, root.
tip() { curl -sf "$DISC/v1/registry/root" | od -An -t u8 -j 1 -N 8 | tr -d ' \n'; }

node_config() { # name listen discovery dial(optional)
  local dir="$RUN/$1"
  mkdir -p "$dir/data"
  {
    echo "data_dir = \"$dir/data\""
    echo "listen_addr = \"127.0.0.1:$2\""
    if [ -n "${4:-}" ]; then echo "dial_peers = [\"127.0.0.1:$4\"]"; else echo "dial_peers = []"; fi
    echo "genesis_file = \"$NET/genesis.qmb\""
    echo "committee_key_paths = []"
    echo "mining = false"
    echo "expected_genesis_hash = \"$REHEARSAL_HASH\""
    echo "discovery_addr = \"127.0.0.1:$3\""
  } > "$dir/node.toml"
}

start_bg() { # name logbase cmd...
  local name=$1 base=$2; shift 2
  "$@" >>"$base.out" 2>>"$base.err" &
  PIDS+=($!)
  echo $! > "$base.pid"
  log "$name up (pid $!)"
}

# One wallet command, measured. who verb args... ; stdout in $LAST_OUT, stderr in $LAST_ERR.
LAST_OUT=""; LAST_ERR=""
wcmd() {
  local who=$1 verb=$2; shift 2
  local d="$RUN/$who" n
  mkdir -p "$d"
  n=$(( $(find "$d" -maxdepth 1 -name "$verb-*.time" | wc -l) + 1 ))
  LAST_OUT="$d/$verb-$n.out"; LAST_ERR="$d/$verb-$n.err"
  /usr/bin/time -v -o "$d/$verb-$n.time" "$WALLET" "$verb" --dir "$RUN/wallets/$who" "$@" >"$LAST_OUT" 2>"$LAST_ERR"
}
ANN=(--net annulet --url "$DISC" --genesis-hash "$REHEARSAL_HASH")

# The v2 address (index 0) of a wallet's active generation.
v2_addr() { "$WALLET" address --dir "$RUN/wallets/$1" --index 0 --candidate-a | awk '/^address \[/{getline; print $1; exit}'; }
v1_addr() { "$WALLET" address --dir "$RUN/wallets/$1" --index 0 | awk '/^address \[/{getline; print $1; exit}'; }

# A wallet's spendable asset-0 total from a verified scan, into $BAL (fails
# loudly when the scan does; never called inside $(…), where a die would
# only end the subshell).
BAL=""
balance0() {
  wcmd "$1" scan "${ANN[@]}" --to "$FAR" || die "the verified scan of $1 failed: $(tail -2 "$LAST_ERR")"
  local v; v=$(sed -n 's/^asset 0 (fee units): \([0-9]*\) spendable.*/\1/p' "$LAST_OUT")
  if [ -z "$v" ]; then
    grep -q '^balance:  no notes in range' "$LAST_OUT" && v=0 || die "no asset-0 line in $1's scan ($LAST_OUT)"
  fi
  BAL=$v
}

# Wait until a wallet's verified balance reaches at least $2 (a grant or a send settling).
await_balance() {
  local who=$1 want=$2 what=$3 got=0
  for _ in $(seq 1 60); do
    balance0 "$who"; got=$BAL
    [ "$got" -ge "$want" ] && { log "$who holds $got (asset 0) — $what"; return 0; }
    sleep 5
  done
  die "$who holds $got (asset 0), not $want, five minutes after $what"
}

grant() { # address
  local body code
  body="$RUN/faucet/grant-$(date +%s%N).body"
  code=$(curl -s -o "$body" -w '%{http_code}' --data-binary "$1" "$FAUCET_URL/v1/annulet/grant" || echo 000)
  [ "$code" = 200 ] || die "the faucet refused a grant: $code $(head -c 300 "$body")"
  log "granted: $(head -1 "$body")"
}

# The (g next) pairs of a journal, one per line.
positions() { sed -n '2,$p' "$RUN/wallets/$1/auth.v1" | awk '{print $1, $2}'; }

# ---- the net ---------------------------------------------------------------------
mkdir -p "$NET" "$RUN/faucet" "$RUN/wallets"
"$NODE" genesis annulet-devnet --rehearsal --out "$NET" --sequencer-data-dir "$RUN/seq/data" >"$NET/genesis.out" 2>&1 \
  || die "genesis annulet-devnet --rehearsal failed (see $NET/genesis.out)"
got=$(sed -n 's/^genesis hash: //p' "$NET/genesis.out")
[ "$got" = "$REHEARSAL_HASH" ] || die "the binary minted genesis $got, not the pinned rehearsal genesis $REHEARSAL_HASH"
log "rehearsal genesis $got"

node_config seq "$P_SEQ" "$P_SEQ_DISC"
node_config follower "$P_FOL" "$P_FOL_DISC" "$P_SEQ"
node_config faucet "$P_FAU_NODE" "$((PORT + 6))" "$P_SEQ"
start_bg sequencer "$RUN/seq/node" "$NODE" run --config "$RUN/seq/node.toml"
start_bg follower "$RUN/follower/node" "$NODE" run --config "$RUN/follower/node.toml"
for _ in $(seq 1 60); do [ -n "$(tip 2>/dev/null)" ] && break; sleep 1; done
[ -n "$(tip 2>/dev/null)" ] || die "the follower's discovery did not answer within 60 s"
grep -q 'ANNULET role=producer' "$RUN/seq/node.out" || die "the sequencer did not come up as producer"
start_bg faucet "$RUN/faucet/faucet" /usr/bin/time -v -o "$RUN/faucet/faucet.time" \
  "$FAUCET" annulet --node-config "$RUN/faucet/node.toml" --listen "127.0.0.1:$P_FAUCET" --fresh-journal
# GNU time forwards no signal: the cleanup stops the faucet itself.
FAUCET_PID=""
for _ in $(seq 1 50); do FAUCET_PID=$(pgrep -P "$(cat "$RUN/faucet/faucet.pid")" | head -1 || true); [ -n "$FAUCET_PID" ] && break; sleep 0.1; done
[ -n "$FAUCET_PID" ] || die "the faucet did not start (see $RUN/faucet/faucet.err)"
PIDS+=("$FAUCET_PID")
for _ in $(seq 1 120); do curl -sf "$FAUCET_URL/" 2>/dev/null | grep -q 'grant(s)' && break; sleep 1; done
curl -sf "$FAUCET_URL/" | grep -q 'grant(s)' || die "the faucet did not answer within 120 s (see $RUN/faucet/faucet.err)"
log "faucet: $(curl -sf "$FAUCET_URL/")"
[ -s "$RUN/faucet/data/faucet-auth/auth.v1" ] || die "the faucet wrote no journal"

# ---- step 1: the acceptance criterion -------------------------------------------
for who in A B; do
  "$WALLET" keygen --dir "$RUN/wallets/$who" >"$RUN/wallets/$who.keygen.out" 2>&1 || die "keygen $who"
  wcmd "$who" migrate "${ANN[@]}" --scan-to "$FAR" || die "migrate $who: $(tail -2 "$LAST_ERR")"
  grep -q '^active generation: 0$' "$LAST_OUT" || fail 1 "$who's first migrate did not open generation 0 ($LAST_OUT)"
done
A0=$(v2_addr A); B2=$(v2_addr B); B1=$(v1_addr B)
[ -n "$A0" ] && [ -n "$B2" ] && [ -n "$B1" ] || die "an address did not print"
[ "$A0" != "$(v1_addr A)" ] || fail 1 "A's v2 address equals its v1 address"
grant "$A0"; grant "$A0"
await_balance A 4 "two grants to A's generation-0 address"
wcmd A send "${ANN[@]}" --scan-to "$FAR" --asset 0 --amount 1 --to "$B2" || fail 1 "A → B v2 send: $(tail -3 "$LAST_ERR")"
grep -q '^sent 1 of asset 0' "$LAST_OUT" || fail 1 "the send printed no sent line ($LAST_OUT)"
await_balance B 1 "A's v2 send"
balance0 A; a_after=$BAL
balance0 B
pass 1 "two grants to A (v2), A → B 1 unit by a signed v2 S through the follower; B holds $BAL, A $a_after"

# ---- step 2: open the next generation --------------------------------------------
wcmd A migrate "${ANN[@]}" --scan-to "$FAR" --open-next || fail 2 "migrate --open-next: $(tail -2 "$LAST_ERR")"
grep -q '^active generation: 1$' "$LAST_OUT" || fail 2 "--open-next did not make generation 1 active ($LAST_OUT)"
grep -q '^generation 0 waits on this net until height [0-9]*' "$LAST_OUT" || fail 2 "generation 0 has no gate ($LAST_OUT)"
A1=$(v2_addr A)
[ "$A1" != "$A0" ] || fail 2 "generation 1's address equals generation 0's"
balance0 B; b_before=$BAL
grant "$A1"; grant "$A1"
await_balance A $((a_after + 4)) "two grants to A's generation-1 address"
wcmd A send "${ANN[@]}" --scan-to "$FAR" --asset 0 --amount 1 --to "$B2" || fail 2 "the generation-1 send: $(tail -3 "$LAST_ERR")"
await_balance B $((b_before + 1)) "A's generation-1 send"
cp "$RUN/wallets/A/auth.v1" "$RUN/A-auth.v1.at-restore"
pass 2 "generation 1 active, generation 0 waits; generation 1 spent once (journal: $(positions A | tr '\n' ';'))"

# ---- step 3: restore → migrate ---------------------------------------------------
# A goes quiet first: from here on only A2 signs for this seed.
mv "$RUN/wallets/A" "$RUN/wallets/A.retired"
"$WALLET" backup --dir "$RUN/wallets/A.retired" --reveal 2>/dev/null \
  | "$WALLET" restore --dir "$RUN/wallets/A2" >"$RUN/wallets/A2.restore.out" 2>/dev/null || die "restore A2"
[ ! -e "$RUN/wallets/A2/auth.v1" ] || fail 3 "a restored wallet already has a journal"
wcmd A2 migrate "${ANN[@]}" --scan-to "$FAR" || fail 3 "A2 migrate: $(tail -2 "$LAST_ERR")"
grep -q '^auth journal created' "$LAST_OUT" || fail 3 "A2's migrate did not create its journal ($LAST_OUT)"
grep -q '^active generation: 2$' "$LAST_OUT" || fail 3 "A2 resumed a used generation: $(grep '^active' "$LAST_OUT")"
for g in 0 1; do grep -q "^generation $g waits on this net until height" "$LAST_OUT" || fail 3 "generation $g has no gate on A2 ($LAST_OUT)"; done
GATE=$(sed -n 's/^generation [01] waits on this net until height \([0-9]*\).*/\1/p' "$LAST_OUT" | sort -n | tail -1)
for g in 0 1; do
  was=$(sed -n '2,$p' "$RUN/A-auth.v1.at-restore" | awk -v g=$g '$1 == g {print $2}')
  now=$(positions A2 | awk -v g=$g '$1 == g {print $2}')
  [ -n "$was" ] && [ "$was" = "$now" ] || fail 3 "generation $g: A's journal is at $was, A2 rebuilt $now"
done
pass 3 "A2 opened generation 2; 0 and 1 wait until $GATE; positions rebuilt from landed leaves equal A's ($(positions A2 | tr '\n' ';'))"

# ---- step 5: a v1 address on this net --------------------------------------------
if wcmd A2 send "${ANN[@]}" --scan-to "$FAR" --asset 0 --amount 1 --to "$B1"; then
  fail 5 "a send to a version-1 address went through"
fi
grep -q 'version 1' "$LAST_ERR" || fail 5 "the refusal does not name the version ($(tail -2 "$LAST_ERR"))"
! grep -q '^sent ' "$LAST_OUT" || fail 5 "the refused send printed a sent line"
pass 5 "a send to B's version-1 address is refused by name: $(grep -m1 'version 1' "$LAST_ERR" | cut -c1-160)"

# ---- step 4: the gate, the sweep, the positions ----------------------------------
log "waiting for the gate: height $GATE (tip $(tip))"
while :; do
  t=$(tip || true)
  [ -n "$t" ] || die "the follower stopped answering while waiting for the gate"
  [ "$t" -ge "$GATE" ] && break
  sleep 15
done
log "gate passed at tip $(tip)"
balance0 A2; a2_before=$BAL
for round in 1 2 3; do
  wcmd A2 migrate "${ANN[@]}" --scan-to "$FAR" || fail 4 "sweep round $round: $(tail -3 "$LAST_ERR")"
  grep -q '^active generation: 2$' "$LAST_OUT" || fail 4 "the active generation moved during the sweep ($LAST_OUT)"
  grep -q 'waits on this net' "$LAST_OUT" && fail 4 "a generation still waits after its gate ($LAST_OUT)"
  grep -q 'move on the next `migrate`' "$LAST_OUT" || break
done
grep -q 'move on the next `migrate`' "$LAST_OUT" && fail 4 "fee notes still left to sweep after three rounds"
balance0 A2; a2_after=$BAL
# Every sweep transaction is sealed before A3 reads the landed leaves: the
# scan above saw the balance after them; a few more seconds (blocks are one
# a second) cover a last one admitted but not yet applied on the follower.
sleep 30
[ "$a2_after" -gt 0 ] || fail 4 "A2 holds nothing after the sweep (it held $a2_before)"
[ "$a2_after" -le "$a2_before" ] || fail 4 "the sweep grew A2's balance ($a2_before → $a2_after)"
"$WALLET" backup --dir "$RUN/wallets/A2" --reveal 2>/dev/null \
  | "$WALLET" restore --dir "$RUN/wallets/A3" >"$RUN/wallets/A3.restore.out" 2>/dev/null || die "restore A3"
wcmd A3 migrate "${ANN[@]}" --scan-to "$FAR" || fail 4 "A3 migrate: $(tail -2 "$LAST_ERR")"
grep -q '^swept ' "$LAST_OUT" && fail 4 "A3 swept: its fresh gates cannot have passed"
for g in 0 1 2; do
  was=$(positions A2 | awk -v g=$g '$1 == g {print $2}')
  now=$(positions A3 | awk -v g=$g '$1 == g {print $2}')
  [ -n "$was" ] && [ "$was" = "$now" ] || fail 4 "generation $g: A2's journal is at $was, landed_next (A3) is $now"
done
pass 4 "swept into generation 2: A2 $a2_before → $a2_after (fees paid); A3's landed positions equal A2's ($(positions A3 | tr '\n' ';'))"

balance0 A2; a2_final=$BAL; balance0 B
log "balances: A2 $a2_final, B $BAL; tip $(tip)"
echo "REHEARSAL-DONE"
log "REHEARSAL-DONE"
