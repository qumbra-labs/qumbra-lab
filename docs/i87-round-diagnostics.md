# Round diagnostics and structured metrics — operator guide (issue #87)

*中文：[i87-round-diagnostics-zh.md](./i87-round-diagnostics-zh.md). EN is authoritative on technical detail.*

This is what a Qumbra node says when a checkpoint round does not finalize, and how to
read it. It exists because for 42 hours it said nothing: the T0 WAN soak measured
14.5–15.9 % of samples in `Degraded` and a `stall` peak of 42 against a threshold of
16, and the four nodes produced **ten** non-telemetry log lines in that entire run,
all of them at startup.

There are two surfaces, and they answer different questions.

| Surface | Question it answers | Where it lives |
|---|---|---|
| `ROUND` journal line | *Why did round 1,384 fail, and who was missing?* | stdout, beside `TELEMETRY` → the container log → the archive |
| `/metrics` | *How often, how long, how bad — over what window?* | HTTP scrape target, **off unless configured** |

They are not redundant. A counter cannot tell you who was absent in one specific
round; a journal line cannot give you a p99. Neither is the other's backup.

---

## 1. The `ROUND` line

One line per round, emitted when the round **closes** — and, for a round that has
been open too long, while it is still open (`close=open`, `why=open`), so a stall is
visible *while it is happening* rather than only once it ends. Same `key=value` shape
as `TELEMETRY`, so the same grep and awk habits work.

```
ROUND slot=1384 epoch=12 why=votes_short close=superseded by=1392 have=11 need=15 active=21 roster=21 \
  voted=0,1,2,3,4,5,6,7,8,9,10 absent=11,12,13,14,15,16,17,18,19,20 excluded=- variants=1 msgs=3 local=6 \
  rej=f0/u0/d0/i0 open_ms=1769000000000 first_ms=211 last_ms=63402 quorum_ms=- closed_ms=600113
```

| Field | Meaning | Caliper |
|---|---|---|
| `slot` | The round number = the checkpoint height on the cadence grid | Genesis (height 0) is **never** a round — it is a bootstrap finalize, with no proposal and nobody to be absent from it |
| `epoch` | Committee epoch the slot is judged against | Read from the epoch schedule; signer indices are only comparable **within** an epoch |
| `why` | The verdict — see §2 | Derived from the other fields; the raw fields are always present so you can disagree with it |
| `close` | `finalized` \| `superseded` \| `evicted` | `evicted` means the open-round cap closed it, not an outcome |
| `by` | The height that overtook this round | Only on `superseded` |
| `have` | Distinct **counting** signers accumulated **at this node** | Across every message this node received. A different node may legitimately record a different `have` — that difference is a gossip-reach finding, not an inconsistency |
| `need` | Quorum threshold in force | Read from the committee state; never re-derived here |
| `active` | Roster minus tombstoned/jailed at this height | `active < need` ⇒ the round was unwinnable regardless of the network |
| `roster` | Committee size at this height | |
| `voted` | Who had a counting vote, by committee index | Ascending |
| `absent` | In the roster, not tombstoned/jailed, and **no vote of theirs reached this node** | Reach, **not** proof the member was down. On a `finalized` round it is also biased toward the slowest peers — see §7 |
| `excluded` | Members whose valid votes were excluded as inactive | Excluded by the frozen §4 rule — do **not** go looking for these hosts |
| `variants` | Distinct checkpoint variants seen at this height | `>1` means a split committee — a different failure from being short of votes |
| `msgs` | Vote-set messages ingested for this round | |
| `local` | Votes this node contributed from its own held keys | `local=0` on a slot this node proposed means every held key was refused by the never-double-sign guard — itself a finding |
| `rej` | `f`orged / `u`nknown-signer / `d`uplicate / `i`nactive | `have=0` with a large `rej` is a very different failure from `have=0` with no traffic |
| `open_ms` | Unix ms when **this node** opened the round | |
| `first_ms`, `last_ms` | Offsets of the first and most recent **new** counting vote | Node-local wall clock; **never difference these across hosts** |
| `quorum_ms` | Offset at which `have` first reached `need` | `-` on a round that never got there |
| `closed_ms` | Offset at which the round closed | |

All timings are `-` under the deterministic clock (every in-process simulation and
the N7 soak). That is deliberate: the node records counts and rosters truthfully and
**does not invent a timing basis it does not have**.

---

## 2. The verdict ladder

`why=` is decided in this order. The first match wins.

1. **`finalized`** — reached quorum.
2. **`backfill`** *(issue #105)* — this node reached the slot as **history**: its own
   tip was already more than one cadence away when it first learned of the slot, so
   there was never a moment at which it could have voted. Every slot a resync walks
   past reads this. **It is not a failure and it is not counted as one** — nothing
   failed, the node was not there. See §2a.
3. **`quorum_impossible`** — `active < need`. The roster could not have produced a
   quorum however well the network behaved. Look at tombstones, jails and the epoch
   boundary; **do not** look at latency.
4. **`silent`** — `have == 0`. Nothing reached this node at all. The problem is
   upstream — the proposer, or the path to it — not participation. Check `rej`: junk
   arriving is a different story from nothing arriving.
5. **`timeout`** — the last *new* vote landed within `STILL_ARRIVING_MS` (60 s) of the
   close. The round was **still accumulating** when it was cut off. More time, or an
   earlier proposal, would plausibly have closed it.
6. **`votes_short`** — votes arrived and then stopped, well before the close. The
   committee gave everything it had and it was not enough. **The `absent` list is the
   finding.**
7. **`unclassified`** — no timing basis (deterministic clock). Never asserted as a
   cause.

`why=open` is **not** a verdict: a round that has not ended has no cause yet. The
counts on such a line are real; only the outcome is undecided, and it is never
counted as a closed outcome. A round is reported open once it has been open longer
than `OVERDUE_AFTER_MS` (600 s = one round period), and reported again when its vote
count moves or `OVERDUE_REPEAT_MS` passes — so a round stuck at `have=11/15` says so
and then stops repeating itself.

**The judgement issue #87 asks for is step 5 vs step 6**, and it is decidable from the
recorded fields alone — `closed_ms`, `last_ms`, `have`, `need`, `active`. That is the
property the journal exists to have, and it is pinned by
`round::tests::diagnosis_separates_timeout_from_votes_short` in both directions,
including the boundary.

`STILL_ARRIVING_MS = 60 s` is **devnet-grade, tunable, NOT frozen**. Basis: the T0
net's measured RTT is 68–223 ms, so a healthy round completes within about a second
of network time; 60 s sits ~270× above the worst measured RTT and ~1/10 below the
600 s round period.

---

## 2a. What `rounds=` and `rfail=` count (issue #105)

`TELEMETRY` carries three counters for this, all **cumulative since process start** —
a restart resets them, deliberately, because this project counts restarts:

```
… rounds=144 rfail=2 … rback=449
```

| field | reads as |
|---|---|
| `rounds=` | **live** rounds this node closed — rounds it was a participant in |
| `rfail=` | of those, the ones that closed **without finalizing**. This is the alarm |
| `rback=` | cadence slots it closed as **history**, i.e. `why=backfill` |

**Read `rfail` as: rounds this node was present for and lost.** Not "slots it walked
past", which is what it used to mean and why it was useless.

A round is **live** iff its slot was within one checkpoint cadence of *this node's
own tip* at the moment the node first learned of the slot:

```
tip − 8  <  slot  ≤  tip + 8
```

Both bounds are the node's own chain. Nothing here consults the sync state machine
(which is entered because a *peer* claims to be taller — a peer advertising an absurd
height would otherwise switch this alarm off for everyone) and nothing consults the
finalized head (which is rebuilt empty at every process start and stays `None` for
the whole of a catch-up, so it cannot carry the judgement).

The verdict is taken **once, when the round opens**, and never revisited. That matters
in one direction specifically: a node mining through a committee outage runs its tip a
long way past a round it genuinely lost, and a close-time test would call that
`backfill` — the alarm switching itself off again by a different route.

### Why it changed

A healthy node that had just resynced 3,597 blocks reported:

```
rounds=1316 rfail=1315        ← 1,315 of 1,316 rounds "failed"
```

…while `peers=6`, `regime=Final`, `variants=1`, and its finalized checkpoint matched
its three peers exactly. The counter was not lying about what it counted; it was
counting the wrong things. **An alarm reading 99.9 % on a healthy node has been
switched off by its own value**, and every node that has ever restarted was in that
state.

### What did NOT change

The `ROUND` journal still records **every** crossed slot — this changed what
increments the counters, not what is recorded. A crossed slot leaving no trace is the
opposite mistake, and it is the one issue #87 exists to have fixed.

---

## 3. Metrics

`/metrics` serves Prometheus text exposition v0.0.4. Every family carries its window
and basis in its `HELP` text, so a number read off the endpoint cannot be separated
from how it was taken.

**Counters and histograms are since process start.** A restart resets them — which is
deliberate, because this project counts restarts, and
`qumbra_process_start_time_seconds` makes one visible.

### The families that did not exist before

| Metric | Type | What it replaces |
|---|---|---|
| `qumbra_finality_regime_seconds_total{regime}` | counter | **The `Degraded` share.** Seconds *accumulated in* each regime, not the fraction of printed samples that happened to be degraded |
| `qumbra_block_interval_seconds` | histogram | The soak's `mean 86 / median 60 / p99 312`, at full event resolution instead of reconstructed from 30 s samples |
| `qumbra_finality_advance_seconds` | histogram | The soak's `median 673 / p90 1802 / max 3161` |
| `qumbra_finality_advance_blocks` | histogram | The 61-of-165 catch-up advances that jumped 16/24/32/40 in one step |
| `qumbra_finality_stall_depth_blocks` | histogram | How deep the stall had gone *at the moment it cleared* — sampled at the event, not differenced off a gauge |
| `qumbra_checkpoint_time_to_quorum_seconds` | histogram | Did not exist. How long a round takes when it works |
| `qumbra_checkpoint_vote_arrival_seconds` | histogram | Did not exist. Per-signer arrival latency within a round |
| `qumbra_checkpoint_rounds_total{verdict}` | counter | Did not exist. Rounds by verdict |
| `qumbra_committee_absent_rounds_total{signer}` | counter | Did not exist. Per-member absence |
| `qumbra_checkpoint_votes_total{result}` | counter | Did not exist. Votes counted vs thrown away, by reason |

Everything else (`qumbra_tip_height`, `qumbra_peers`, `qumbra_mempool_size`,
`qumbra_committee_*`, …) is a **gauge**, because a level's current value is the whole
of its meaning.

### Why these are histograms and not gauges

A printed gauge has already discarded every value it held between two prints. A p99
recovered from 30 s samples is a p99 *of the samples*. The information is destroyed at
print time, not at parse time, so no amount of care in the parser recovers it — which
is why each of these is fed at the event that produces it.

Bucket bounds are chosen against the measured T0 numbers (see the constants in
`qlab-node/src/metrics.rs`) and are **devnet-grade, tunable, NOT frozen**.

### Cardinality

Label values are static tokens and decimal integers only. The per-signer families are
bounded by the **committee roster**, a consensus quantity — never by anything a peer
can send, because a signer index is validated against the roster before it is
counted. There is no operator- or peer-supplied string anywhere in a label.

---

## 4. Turning the endpoint on

**Off by default. No `metrics_addr`, no listener.** An endpoint that exists only where
somebody asked for it cannot be left open by forgetting to turn it off.

```toml
# node.toml
metrics_addr = "0.0.0.0:9090"
```

or, through the deploy tooling:

```sh
deploy/deploy.sh --hosts hosts --metrics-port 9090 …
```

Notes an operator has to have:

* **A failed bind is fatal.** The node refuses to start rather than run
  un-observable while believing otherwise.
* **`deny_unknown_fields` is deliberate.** A config carrying `metrics_addr` will be
  *refused* by a binary built before this change. **Ship the binary first, then the
  config** — never the other way round.
* **Binding is not access control.** Pair a non-loopback bind with an inbound rule
  whose **source is the collector's fixed address or security group** — never
  `0.0.0.0/0`, and never a roaming operator IP. A roaming source re-creates the
  10.15 h blind spot of the 42 h soak in a new place: the SSH path broke for exactly
  that reason. Use standalone `aws_security_group_rule` resources; inline rules once
  silently deleted twelve peer P2P rules.
* **The node serves a pre-rendered snapshot**, refreshed every 5 s by the run loop. A
  scrape costs a string clone and can never contend with the consensus loop for node
  state — which matters on a 2 vCPU host. Read staleness from
  `qumbra_metrics_rendered_timestamp_seconds`; do not assume scrape time.
* **7-day retention is monitoring, not evidence.** Anything only visible through
  Prometheus is gone in a week. Archive the node's own output and cite the archive.

---

## 5. Cost

The round journal is **always on**, and the reason it can be is that the round rate is
set by the **checkpoint cadence, not the block rate**:

```
cadence 8 × 75 s  = 600 s per round  =  144 rounds/day
144 rounds/day × ≤ 400 B/line        ≈  ≤ 58 KB/day
```

Plus the still-open reports, which are zero in normal operation (rounds close in
milliseconds — the lab net's first round closed at 315 ms). They appear only during a
stall, at most one line per open round per vote-count change or per 600 s, and open
rounds are capped at `MAX_OPEN_ROUNDS = 16`. A 40-block stall — the worst the 42 h
soak saw — holds ~5 open rounds and adds well under 100 lines for its whole duration.

Both halves are machine-checked:
`round::tests::journal_line_stays_within_the_quoted_budget` pins the line length for a
fully-populated 21-member round, and
`run::tests::round_journal_volume_is_set_by_the_cadence_not_the_block_rate` derives
the daily figure rather than asserting it by hand.

At that volume a switch would cost more than it saves — and a diagnostic that is off
when the incident happens is not a diagnostic. The metric surface adds a ~14 KB
exposition per scrape and a 5 s render.

---

## 6. Recipes

Find every round that did not finalize, with its cause:

```sh
grep '^ROUND ' node.log | grep -vE 'why=(finalized|open)'
```

Watch a stall as it happens (the still-open reports):

```sh
grep '^ROUND ' node.log | grep 'why=open'
```

Which members are missing most often (over the archived log, all rounds):

```sh
grep '^ROUND ' node.log | sed 's/.* absent=\([^ ]*\).*/\1/' | tr ',' '\n' \
  | grep -v '^-$' | sort -n | uniq -c | sort -rn | head
```

Is the stall latency or participation?

```sh
grep '^ROUND ' node.log | grep -c 'why=timeout'      # latency-shaped
grep '^ROUND ' node.log | grep -c 'why=votes_short'  # participation-shaped
```

PromQL, once a collector is in place:

```promql
# The Degraded share over the last day — measured residency, not sampled
rate(qumbra_finality_regime_seconds_total{regime="degraded"}[1d])

# Round failure rate by cause. `backfill` is excluded on purpose (issue #105):
# it is history this node walked through, not a round it lost, and leaving it in
# is what made this number read 99.9 % on a healthy node.
rate(qumbra_checkpoint_rounds_total{verdict!="finalized",verdict!="backfill"}[1h])

# How much history this node has crossed — the restart/resync signature, and a
# fact worth having, but never an alarm.
rate(qumbra_checkpoint_rounds_total{verdict="backfill"}[1h])

# Which member is dragging: absence rate per signer
rate(qumbra_committee_absent_rounds_total[1h])

# p99 time-to-quorum
histogram_quantile(0.99, rate(qumbra_checkpoint_time_to_quorum_seconds_bucket[1h]))

# Catch-up advances: finality moving more than one cadence at a time
rate(qumbra_finality_advance_blocks_bucket{le="8"}[1h])
  / rate(qumbra_finality_advance_blocks_count[1h])
```

---

## 7. What this does *not* tell you

Stated so nobody reads more into a record than it holds.

* **`absent` is not proof a member is down.** It is "no vote of theirs reached this
  node before this round closed". A member that is up but partitioned from *this* node
  is absent here and present elsewhere. Comparing the same slot's `absent` across the
  four nodes is how you tell those apart — and that comparison is now possible, which
  it was not before.
* **On a `finalized` round, `absent` is biased toward the slowest peers.** A round
  closes the *instant* quorum is reached, so members whose votes were 50 ms behind the
  15th are recorded absent. The first lab-net round shows exactly this: it closed at
  `quorum_ms=315` with `have=16`, and the five keys held by the most distant node are
  in `absent` — they were late, not down. `qumbra_committee_absent_rounds_total`
  inherits the bias. **The unbiased read is on failed rounds**, which stay open far
  longer: filter the journal on `why!=finalized`, or read the metric against
  `qumbra_checkpoint_rounds_total{verdict!="finalized",verdict!="backfill"}` — a
  `backfill` round has nobody present to be absent from. Used this way the counter
  answers "who is missing when it matters"; used naively it answers "who is furthest
  away", which is a real thing to know but a different one.
* **Timings are node-local and unsynchronized.** `first_ms`/`last_ms`/`quorum_ms` are
  offsets from *this node's* open instant on *this node's* wall clock. Never
  difference them between hosts.
* **`have` is this node's view.** The authoritative quorum gate is unchanged and
  upstream of every one of these records; nothing here can make something finalize or
  stop it finalizing.
* **A verdict is a reading of the fields, not a measurement.** The raw fields are
  always on the line. If you disagree with `why=`, the evidence to disagree with is
  right there.
* **This does not answer why `DEGRADED_MODE_LAG_BLOCKS = 16` is or is not the right
  threshold.** It produces the evidence that question needs. The constant is FROZEN
  and untouched here; changing it is a halt-height upgrade and a separate act.
