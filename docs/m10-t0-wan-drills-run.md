# M10 Phase B-WAN — the four scenario drills, run 2026-08-07 (scope: **WAN**)

> [中文版](m10-t0-wan-drills-run-zh.md)

**R1: this document is evidence, not a verdict.** It records what four drills produced on the
live T0 net — readings, timestamps, and the things that went differently from the plan. It
contains no PASS, no summary of a run as successful, and no adjudication of the findings it
reports. Those belong to the coordinator.

The drills are the last item M10 Phase B-WAN owed. The ≥48 h continuity soak was sealed
2026-07-28 (PR #93); these four scenarios were held for two years' worth of preconditions in
nine days — `fid` on the wire (#84), the state-machine lag reading (#130 a), the cold-start
mining gate (#106 item 1), the durable head (#212), and finally the drill instruments
themselves (#241 typed refusal reasons, #226 per-variant `have=`), which landed on the fleet
the day before this run.

---

## 1. Provenance

| | |
|---|---|
| Net | T0-WAN, genesis `138e1524ba889bd49644f0eeafafa53533584caa2c0c851330cd27965223addb`, format v4 |
| Hosts | 4 × AWS `t4g.small` (Graviton/arm64, Debian 12): node0 us-east-1 (6 keys) · node1 eu-west-1 (5) · node2 ap-southeast-1 (5) · node3 ap-northeast-1 (5). Committee 21 keys, quorum 15 |
| Image | `ghcr.io/qumbra-labs/qumbra-node@sha256:988c9f5d…a988` = `t0-wan-13`, revision `1d7fabbd…`, revision label read back per host |
| Rolled | 2026-08-06 10:21–11:04 +08, one host at a time under the amended per-host gate (`qumbra-deploy/tasks/roll-t0-wan-13-2026-08-06.md`) |
| Entry gate | six checks, met 2026-08-07 13:25 +08 — evidence `qumbra-ops/drills-138e1524/gate/` |
| R3 | granted 2026-08-06 07:31 +08 for all four drills; extended 2026-08-06 20:25 +08 to cover D4's dead-man heal |
| Raw evidence | `qumbra-ops/drills-138e1524/{gate,d1,d2,d3,d4}/` — per drill: `before/`, `during/`, `after/`, `FINDINGS.md` |
| Clocks | hosts UTC, operator rig +0800. Every timestamp below carries its zone |

**Entry gate as measured.** 26 h 19 m of sampling since the roll (277 samples), five
`schain=fork` occurrences **each resolved by the next sample for that host** (none persisted,
which is the bar's wording), zero STOP-class strings, all four `restarts=0` since the roll,
`fid` agreed. Two observation holes — 1 h 17 m and 40 m, both caused by the operator's laptop
sleeping with the lid closed in transit — were **filled from the primary record** (container
logs) and both were clean: `qumbra-ops/recovered-gap-0806/`, `recovered-gap-0807am/`.
`caffeinate -i` bounds idle sleep and does not prevent a closed lid; that is now written into
the run book rather than hoped against.

---

## 2. D1 — mining-node restart (node2)

**What was done.** Ring archived; `docker compose stop` (graceful, `stop_grace_period: 30s`);
`docker compose start`; observed to `mready=synced`.

```
13:26:14  before: all four tip=3157 final=3152 fid=e153e4ff0d08 slag=0 restarts=0
13:26:30  stop issued
13:27:01  container FinishedAt — exitcode=137 (128+9 = SIGKILL): the 30 s grace expired
13:27:45  start; container running
          ... 15 m 31 s of ZERO log output at CPU 100.38%, RSS 11.86 MiB ...
13:43:16  RECOVERY restored snapshot at height 1868, replayed 1987 records, resumed at tip 3157
          CPU → 4.98%, RSS → 270 MiB
13:47:58  node2 rejoined: tip=3172 final=3168 fid=3fb176af7bb8 slag=0 mready=synced
```

**Three things this produced.**

1. **The graceful stop did not flush.** No shutdown output; `snapshot.bin` and `peers.dat`
   still carried their container-start mtimes. Filed as lab #286 — and **corrected 46 minutes
   later** by D2 (see §3): the flush is intermittent, not absent.
2. **`replayed 1987 records` — the first non-zero `blocks.log` replay this project has ever
   observed.** Lab #104's closing condition, recorded on that issue. It happened *because* the
   flush failed: the snapshot on disk was 26 h stale at height 1868.
3. **A 15-minute replay that prints nothing is indistinguishable from a hang.** Filed as lab
   #287. The operator reading at the 12-minute mark recorded the leading hypothesis as #106
   item (2)'s unexplained wedge and argued RSS 11.86 MiB ruled out a replay; **that inference
   was wrong** — the replay runs before the RandomX cache loads and coinbase-only state barely
   moves RSS. The run book's instruction in that situation ("do not restart, it may
   self-resolve") is what preserved the observation.

**The net during D1**, with node2's 5 keys absent (16 remain ≥ quorum 15): node0/1/3 at
tip=3168-3169, `final` advancing 3160 → 3168, `fid` agreed, `slag=0`, `peers=4`.

---

## 3. D2 — late-joiner sync (node3)

There is no fifth host, so "late joiner" here is a member that missed a stretch of chain and
must catch up from peers.

```
14:12:36  stop issued
14:12:38  exitcode=0 in 2 s — "shutdown complete (snapshot flushed)"
          snapshot.bin 225181 B and peers.dat both mtime 06:12Z — the flush RAN
          ... down 60 m 39 s (planned 45; the window simply ran longer — recorded, not rounded) ...
15:13:42  start
15:13:46  RECOVERY restored snapshot at height 3189, replayed 0 records, resumed at tip 3189   (4 s)
15:14:21  tip=3233 final=3216 peers=6 fid=016085340d11 slag=0 mready=synced rounds=2
          => 44 blocks of catch-up from peers in under 39 s, votes re-entered
15:14:38  all four: tip=3233 final=3216 fid=016085340d11 stip=3233 slag=0 peers=6
```

**During the hour node3 was down**, the other three finalized continuously: `final` 3184 →
3192 → 3200 → 3208 → 3216, `fid` changing at each step, `slag=0`, `peers=4`. **A 5-key
member's absence does not stop finality** — the 6/5/5/5 topology's quorum claim, measured.

**The A/B this pair produced, unplanned:**

| | D1 node2 | D2 node3 |
|---|---|---|
| shutdown | hung, SIGKILL at 30 s, no flush | clean, exit 0 in 2 s, flushed |
| snapshot on disk | 26 h stale (height 1868) | fresh (height 3189) |
| restart → RECOVERY | **15 m 31 s**, silent, 100 % CPU | **4 s** |
| records replayed | **1987** | **0** |

Same image, same compose, same key count, 46 minutes apart. Lab #286 was retitled on this
evidence: the shutdown flush is **intermittent**. Four stops were performed across D1–D3;
**one hung** (node2). A hypothesis worth testing rather than assuming — node2 was mining when
SIGTERM arrived, and a mining attempt with a large nonce budget is the obvious candidate for a
section that does not observe the shutdown flag — is recorded on #286 as a hypothesis, not a
cause.

---

## 4. D3 — committee stall → recovery (node1 + node3 stopped)

Stopping node1+node3 removes 10 keys; 11 remain, below the quorum of 15, with the net
otherwise fully connected.

**Quorum arithmetic pinned before the stall**, because this is where a false R2 is easiest:

```
07:17:11.84Z  node1 stopped (5 keys leave; 16 remain)
07:17:13.88Z  ROUND slot=3232 why=finalized have=16 need=15 absent=11,12,13,14,15 variants=1
              => finalized on a REAL quorum of 16, two seconds after node1 left
07:18:27.24Z  node3 stopped (11 remain — below quorum). Everything after this is the drill.
```

**The stall, 23.5 minutes:**

```
15:19  tip=3238 final=3232 stall=6  regime=Final
15:31  tip=3245 final=3232 stall=13 regime=Final
15:37  tip=3249 final=3232 stall=17 regime=Degraded
15:40  tip=3251 final=3232 stall=19 regime=Degraded
```

`final` frozen at 3232 while `tip` advanced 3238 → 3251 — the two live hosts kept mining and
finalized nothing. The round that says why, printed twice eleven minutes apart, unchanged:

```
ROUND slot=3240 why=open close=open have=11 need=15 active=21 roster=21
      voted=0,1,2,3,4,5,11,12,13,14,15   absent=6,7,8,9,10,16,17,18,19,20
```

`have=11` is exactly node0's 6 + node2's 5; the ten absent indices are exactly the stopped
hosts' keys. This is **#87's votes-short-vs-timeout discriminant on its first live outing**,
read through **#226's corrected `have=`** — the number means single-variant votes, so "11 of
15" is unambiguous. Under the pre-#226 instrument the same round printed a cross-variant total;
that ambiguity cost five hours on 2026-08-02.

**The heal:**

```
07:43:41Z  node3 start → 07:43:47Z  RECOVERY … replayed 0 records   (6 s)
07:44:53Z  node1 start → 07:45:00Z  RECOVERY … replayed 0 records   (7 s)
07:47:15Z  ROUND slot=3240 why=finalized have=16 need=15  quorum_ms=1576455  (26 m 16 s open)
07:47:15Z  ROUND slot=3248 why=finalized have=16 need=15  quorum_ms=646021   (10 m 46 s)
07:48:38Z  ROUND slot=3256 why=finalized have=16 need=15  quorum_ms=156332   ( 2 m 36 s)
```

**Finality closed the whole stalled span in order, not by skipping it.** Each round's
`quorum_ms` is its own age. Nothing was burned: the votes cast by the surviving 11 stayed in
the tally and the returning 10 completed each round in sequence — the contrast with §5 is the
point, and with the 2026-08-05 incident, where every key had already committed to a variant.

---

## 5. D4 — 2+2 partition → heal

Split **A = {node0, node2}** (11 keys) | **B = {node1, node3}** (10 keys), the stamped
topology; each side spans one of the two longest links. Both sides below quorum by design.
Cut applied on side A only, port 9444 both directions. **Dead-man heal armed on both A hosts
in the same paste as the cut** (2400 s), per the run book's 2026-08-06 amendment.

```
16:00:37/40  cut applied; rules verified in place on both A hosts
16:01:07/08  dead-man armed
16:32:26     deepest divergence: node2(A) tip=3289 stipid=fd4134ebd4ed
                                 node1(B) tip=3289 stipid=66df395898cc
                                 final=3264 frozen on all four, regime=Degraded, stall=25
16:32:53/57  cut removed (0 rules remain); dead-man cancelled WITHOUT firing
16:47:20     FINALITY RESUMED: final 3264 → 3296
16:52:06     node2 DIALs node1, REWINDs, adopts the winning branch
16:53:50     all four: tip=3304-3305 final=3296 fid=b9869e62fcbd regime=Final slag=0
```

**Three findings.**

1. 🔴 **`peers=` and `dialable=` do not see a silent partition.** Fourteen minutes into the
   cut every host still printed `peers=6 dialable=3/3` — the exact reading the run book told
   the operator to use to confirm the cut. `iptables -j DROP` is silent, so the TCP connections
   stayed `ESTABLISHED` with ~55 KB wedged in each send queue; the node counts sockets. **The
   readings that did see it** were `stipid` divergence at equal height and frozen `final` with
   climbing `stall`. The run book's verification step has been corrected in `qumbra-deploy`.
2. **The partition burned one checkpoint slot per cadence crossed.** Finality resumed by
   jumping 3264 → 3296, superseding 3272/3280/3288 — each side's keys had signed its own
   variant while split. Observed rounds: `slot=3272 have=11 voted=0,1,2,3,4,5,11,12,13,14,15`
   (side A's eleven), then `slot=3280 have=5 voted=11,12,13,14,15` (node2 alone, node0 having
   already crossed to the winning branch). This is #269's mechanism, produced deliberately.
3. 🔴 **A host stayed on the losing branch for ~20 minutes after the network was whole, while
   every field on its own telemetry line reported health** — `tip=3291 stip=3291 slag=0
   mready=synced peers=6 dialable=3/3 bask=0@3291 unk=0/0`. The wedged socket to node1
   persisted `ESTABLISHED` with 191,846 bytes in its send queue; the node counted it as a live
   peer and therefore never re-dialed. Convergence arrived on a kernel timeout, not a node
   decision: the socket cleared at 16:51:32, the DIAL and REWIND followed at 16:52:06. Only the
   **cross-host `fid` comparison** exposed it. Filed as lab #289.

**Dead-man outcome, recorded as evidence:** cancelled without firing —
`/tmp/qumbra-deadman.log` is 0 bytes on both hosts, created at arming, never written. Note for
anyone repeating this: **killing only the `sleep` would have FIRED it, not cancelled it**, since
`sh` would then run the heal body immediately; the parent must be killed, and the empty log is
the proof of a clean cancel.

---

## 6. Honest remainders

- **No R2 STOP-POINT occurred in any drill.** `final` never regressed, never advanced without a
  quorum, no two checkpoints were finalized at one height, and no host diverged *past* a
  finalized checkpoint (node2's D4 divergence was behind the finalized head at 3264).
- **D2 ran 60 m 39 s against a planned 45 m**; the operator did not issue the restart at the
  planned time. Recorded rather than rounded; it made the catch-up distance 44 blocks.
- **D1's silent window was read wrong in flight** and the misreading is preserved in
  `d1/FINDINGS.md` with its correction. The evidence available at the 12-minute mark genuinely
  did not distinguish a replay from a hang — that is #287, not hindsight.
- **D4's non-convergence was first recorded as "stranded, mechanism open"** and corrected 8
  minutes later when the host self-healed. Both texts stand in `d4/FINDINGS.md`.
- **The catch-up curves were not resolved.** D2's node3 was already `mready=synced slag=0` at
  the first reading 39 s after start; the shape between 3189 and 3233 is unmeasured. Same for
  D4's convergence.
- **CPU readings in the after-states are single `docker stats --no-stream` samples** and
  measure nothing; mining is bursty and no drill instrumented it. Noted so no finding is read
  into them.
- **Nothing was wiped and no host was restarted outside the drill steps.** node2's D4
  divergence was left untouched until it resolved itself; the run book's recovery-by-wipe path
  was never invoked and remains an unexercised procedure.
- **`stop_grace_period` was not varied.** Whether 30 s is simply too short for the flush at
  this chain length, versus the shutdown path hanging outright, is unresolved by these drills
  (#286).

## 7. Issues filed from this run

| | |
|---|---|
| [#286](https://github.com/qumbra-labs/qumbra-lab/issues/286) | the shutdown flush is intermittent — one hang in four stops; SIGKILL at the grace boundary leaves a stale snapshot |
| [#287](https://github.com/qumbra-labs/qumbra-lab/issues/287) | a 15-minute `blocks.log` replay prints nothing and is indistinguishable from a hang |
| [#289](https://github.com/qumbra-labs/qumbra-lab/issues/289) | after a partition heals, wedged sockets keep a node from re-dialing for ~20 min while telemetry reports health |
| [#104](https://github.com/qumbra-labs/qumbra-lab/issues/104) | closing condition met — first `replayed N>0` observation, recorded on the issue |
