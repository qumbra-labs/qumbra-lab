# Incident record — the `t0-wan-7` roll, 2026-08-02

中文: [`incident-2026-08-02-t0-wan-7-roll-zh.md`](./incident-2026-08-02-t0-wan-7-roll-zh.md) — EN is
authoritative on technical detail.

**What this is.** A four-host upgrade roll that stopped after one host, cost about five hours of
finality, an unnecessary data-dir wipe, and produced four measured constants and three corrections to
the coordinator's own diagnosis. **No R2 stop-point was reached at any moment.** Nothing was
finalized twice, no chain diverged past a finalized checkpoint, and `fid` agreed across the fleet
throughout.

**Why it is written.** The findings are already in issues. **What is not in the issues is the
sequence in which the diagnosis was wrong**, and that is the part a reader repeats if nobody records
it.

---

## 1. Timeline

All times UTC. The coordinator produced the evidence from `13:40Z` onward and also ruled on it; see
§7.

| time | |
|---|---|
| `12:39–12:50` | T-ops read-only sample: `final` frozen at 1976 for 83 min, node0 and node2 `schain=fork` with `stip` unmoved and `breq=1`, `tip` advancing normally |
| `13:12:10` | **node2 self-recovers. `restarts=0`, container untouched for 33 h.** Frozen 2 h 21 m 04 s |
| `13:26` | Coordinator rules *do not roll*; predicts node0 recovers ≈ `13:53Z` on node2's interval |
| `~13:45` | **node0 self-recovers, `restarts=0`.** Frozen ≈ 2 h 13 m — **prediction within ~8 min** |
| `14:37:26` | node1 rolled to `t0-wan-7`. Nine-field tail present, `fid` agrees, `dfin=2112` = `final` |
| `14:44:32` | node2 rolled. **Crash-loop, 19 restarts**, every line `rewind refused: rewind target is not a known block` |
| `14:57` | Rollback to node2's previous image — **fails identically** |
| `15:08` | node2's chain state moved aside and restarted; `tip=0`, resync begins |
| `15:01–17:25` | node1 stranded, 2 h 23 m, peak `slag=87`, **`uex=0` throughout** |
| `14:36–22:45` | **`final` stalled at 2120 → 2456 → 2496.** Roughly five hours in total, in two stretches |
| `17:02` | Offline replay investigation completes — **all four logs replay clean** |
| `22:39` | node1 rescued: stop, move `snapshot.bin` aside, start. `RECOVERY no snapshot, replayed 3032 records` |
| `22:45` | **`final` 2456 → 2496, 21 of 21 keys, `age_s` 4250 → 294** |

## 2. What actually broke

🔴 **`snapshot.bin` is written in exactly one place — the graceful-shutdown flush — with no periodic
write.** So the artifact that decides whether a node can restart is minted **by the stop that
precedes every roll**, and `resume_from_snapshot` propagates a rewind refusal with `?` instead of the
`Ok(None)` fall-through **its own comment calls the discipline**. The always-correct full replay sits
one line away and is not taken. [`#225`](https://github.com/qumbra-labs/qumbra-lab/issues/225).

**The roll minted the poison and then ate it, seconds later.** That is why the rollback failed
identically — the log was never the problem and the rollback never touched the snapshot.

**Measured, 800 simulated graceful stops across the four hosts' real logs:**

| host | stop points that refuse to start |
|---|---|
| **node0** | **12 / 200 — 6.0 %** |
| node1 · node2 | 5.0 % |
| node3 | 3.0 % |

## 3. Why finality stalled, which is a different question

**Not the roll.** With node1 stranded, the fleet had 16 of 21 keys available against a quorum of 15.
**That is a margin of one, and a fork race consumes it.**

The `ROUND` line at slot 2480, on three hosts independently:

```
slot=2480 why=open close=open have=16 need=15 variants=2
```

**Sixteen votes, split across two checkpoints.** node0's 6 on one, node2+node3's 10 on the other.
**Neither reaches 15.** The never-double-sign guard then locks each host out of that slot
permanently — correctly — and the net must skip to the next one.

🔴 **`have=16 need=15` with `close=open` reads as a contradiction.** `have` counts *total* votes,
not votes on one variant. An operator cannot tell why the round did not close without also reading
`variants`. That is an instrument defect in its own right and it is
[`#226`](https://github.com/qumbra-labs/qumbra-lab/issues/226).

## 4. Four measured constants

**The self-recovery interval, three hosts, three image versions, zero interventions:**

| host | frozen for |
|---|---|
| node0 | ≈ 2 h 13 m |
| node2 | 2 h 21 m 04 s |
| node1 | 2 h 23 m |

**Close enough that the interval looks like a property of the mechanism rather than a coincidence.**
It is what makes *waiting* a defensible response rather than an anxious one — and the 13:26 ruling
predicted node0's recovery from node2's number to within about eight minutes.

**`uex` never armed.** 817 consecutive `TELEMETRY` samples on node1, the only host carrying `#199`
and `#201`, across two strandings of 2 h 23 m and 1 h 40 m. Distinct values of `uex` across all 817:
**`{0}`**. The arming threshold is 16 blocks ≈ 20 minutes. [`#222`](https://github.com/qumbra-labs/qumbra-lab/issues/222).

**Recovery cost.** Full replay of a ~3,000-record log: **under four minutes** from `docker compose
down` to `slag=0`, against a measured estimate of 84.5 s for the replay itself.

**Roll verification.** `t0-wan-7`'s nine-field tail — `… bdrop= unk= cpq= dfin= fdrop=` — appeared on
node1's first line, with `dfin=2112` equal to `final=2112`. **The first production reading of the
durable finalized head, and it was healthy.**

## 5. Three corrections to the coordinator's own diagnosis

**Recorded because the sequence is the lesson, not the conclusion.**

**(a) *"node2's data dir was already unreplayable before I rolled it — the roll merely revealed
it."*** **Wrong, and backwards.** All four logs replay clean. The roll's own shutdown flush minted
the poison. The correction came from an independent replay of the artifacts, with node1's log as the
control — **without that control the result would have been unfalsifiable.**

**(b) The wipe was unnecessary.** Moving `snapshot.bin` aside restores the identical state with no
resync, in ~85 s. **The wipe cost the net five keys for hours.** `blocks.log` and `snapshot.bin` were
moved to `/tmp` rather than deleted, so nothing is lost — but the decision was wrong and the reason
was that the recovery had not been discovered yet.

**(c) *"`cpq=1` is sustained and cannot clear on a mixed net."*** **Cleared in four minutes**, by
re-gossip refilling the tally, with no peer able to answer the query. **`#204`'s fetch is for the
tail case — a slot old enough that nothing re-gossips — not the ordinary one.** The ordinary case
self-heals, which is why the gap went unnoticed for so long. I withdrew the pre-registered reading I
had proposed for the second host along with it.

## 6. What changed procedurally

**The rig became a real mutex** ([`PR #217`](https://github.com/qumbra-labs/qumbra-lab/pull/217)).
The old protocol was *check `ps`, post a START line on issue #64* — check-then-act, which issue #64
records losing three times, including once to a measurement that read **2.1× its true value**.
`mkdir` is atomic; a `ps` snapshot is not. **It binds the coordinator too**, which was the hole at
the top.

**CI runs only on the tree somebody reads** ([`PR #210`](https://github.com/qumbra-labs/qumbra-lab/pull/210)).
Roughly half the month's Actions spend was buying numbers nobody looked at.

**R1 was split by what the evidence is for, not by role**
(`qumbra-deploy` `PR #50`). Read-only sampling is either session; evidence packs and drill pass/fail
stay with T-ops; **and when the coordinator produces evidence it rules on, the ruling says so in its
own text.** The point is that the weakening is visible rather than silent.

**Move `snapshot.bin` aside before every roll** (`qumbra-deploy` `PR #52`), binding until `#225`'s
fix is **deployed** on the host being rolled — not merged, not on `main`.

## 7. Evidence held, and the disclosure

**Artifacts**, all read-only captures. Nothing under `/opt/qumbra` that is a key, a genesis or a
`.env` was opened.

- four hosts' `blocks.log` (380–383 KB each)
- node2's `snapshot.bin` (148,573 B) and its 20-line crash-loop log
- node1's full container log, 1,277 lines, `14:37Z → 22:39Z`
- node1's pre-rescue `snapshot.bin` (171,757 B), **kept rather than deleted** — if it was poisoned it
  is the second sample of `#225` and the only way anyone would know

🔴 **Disclosure.** From `13:40Z` the coordinator produced the operational evidence and also ruled on
it — built the branch, pushed the image, performed the rolls, took the samples, and wrote the
findings. **The mitigations are that the pass/fail table was pre-registered and merged before the
roll, and that the replay investigation was run independently with a control.** T-ops produced the
`12:39Z`/`12:50Z` samples and the initial archive.

## 8. What is still open

| | |
|---|---|
| [`#225`](https://github.com/qumbra-labs/qumbra-lab/issues/225) | the fix — dispatched, **blocks the remaining three hosts' roll** |
| [`#222`](https://github.com/qumbra-labs/qumbra-lab/issues/222) | `uex` never arms; and whether `#201` addresses this shape at all, given every stranded host kept mining normally |
| [`#223`](https://github.com/qumbra-labs/qumbra-lab/issues/223) | slot lockouts and the quorum margin nobody counts |
| [`#226`](https://github.com/qumbra-labs/qumbra-lab/issues/226) | `have=16 need=15 close=open` reads as a contradiction |
| — | **node1 stranded twice in eight hours.** The rescue treats the symptom; the shape is untouched |

## 9. The sentence this incident is for

**Nothing anywhere asks a running node whether its own persisted state would open.** node2 ran
perfectly — `fid` agreeing, participating in quorum, `slag=0` — with a snapshot that would refuse to
start, and the first thing that asked the question was the roll. **That is this project's recurring
shape at its most expensive: a healthy reading that is not a reading of health.**
