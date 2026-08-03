# TELEMETRY field reference (issue #173)

*中文版：[`telemetry-field-reference-zh.md`](telemetry-field-reference-zh.md)。EN is authoritative on technical detail.*

Every field on the `qumbra-node` `TELEMETRY` stdout line, what it counts, what a
normal value looks like, what a change means, and — the column this document
exists for — **whether it is ever an alarm on its own.**

Written for an operator who has not read the code and is looking at one line on
one host, under time pressure. Every row is derived from the source that renders
the field and the issue that introduced it; where a source comment already says
it better than a paraphrase would, it is quoted rather than restated.

**The failure this document is fixing.** On 2026-07-31 and again on 2026-08-01 a
T-ops session met `rback=` cold, could not act on it, and both times wrote a
version of *"I do not know that field's semantics and am not inferring from it."*
That was the correct call and it must keep being the correct call — R1 exists so
an operator reports rather than guesses. But the answer was in
`crates/qumbra-node/src/run.rs:879` the whole time, and resolving it cost
coordinator time twice.

---

## 0. How to read the line

The line is emitted to stdout every `TELEMETRY_REFRESH` interval by
`RunningNode::telemetry_sample` (`crates/qumbra-node/src/run.rs:826`). The field
order is the `format!` at `run.rs:996`:

```
TELEMETRY tip= final= stall= age_s= diff= peers= mempool= epoch= regime= halt= hignore= powrej= dialable=<n>/<n> rounds= rfail= fid= sslot= sid= rback= stip= slag= uanchor= mready= stipid= schain= breq= fback= prest= uex= bdrop= unk=<n>/<n>
```

⚠️ **That is the field list, not a capture.** The only values quoted in this
document as observed are the ones attributed to a named issue or evidence pack;
everything else is derived from the source. A composite "typical line" would be a
figure with no caliper, which is what this project keeps getting bitten by.

Five rules that hold for the whole line:

1. **It is positional and append-only.** Every field keeps its name, position and
   meaning forever; new fields are appended at the end. Two tests enforce this:
   `telemetry_line_is_extended_at_the_end_and_nowhere_else` and
   `the_pre_i84_telemetry_prefix_is_frozen_against_future_appends`
   (`run.rs:3492`, `run.rs:3556`). A parser that does not know a field simply
   does not read it.
2. **`-` means "this node will not state a figure it cannot stand behind."** It is
   never an error and never a zero. Which fields can print it, and why, is in
   each row.
3. **Counters are cumulative since PROCESS START, not since the mint.** `rounds`,
   `rfail`, `rback`, `hignore`, `powrej` and `uanchor` all reset to 0 on restart.
   **Comparing a counter across a host that restarted and one that did not is
   comparing two different windows** — this is the single most common way to
   misread the line.
4. **Heights (`tip`, `final`, `stip`, `stall`, `epoch`, `halt`) are chain facts**
   and are comparable across hosts directly.
5. **`age_s` is chain time, not wall time** — it is a difference of block
   timestamps, so it is deterministic given the chain and does not tick while you
   watch.

### The alarm column

| token | meaning |
|---|---|
| 🟢 **never** | No value of this field, alone, justifies escalation. Reading it as an alarm produces false positives. |
| 🟡 **not alone** | Real signal, but only against a second field or a cross-host comparison. The row names which one. |
| 🔴 **yes** | One named value or transition, on one host, is enough. The row names it exactly. |

### Every field at a glance, in the order the line prints them

| # | field | one line | alarm alone? |
|---|---|---|---|
| 1 | `tip` | fork-choice tip height | 🟢 never |
| 2 | `final` | finalized head height, `-` if nothing finalized | 🔴 **yes — if it goes backwards, including `N` → `-`** |
| 3 | `stall` | `tip − final` | 🟢 never (it is `regime` in another unit) |
| 4 | `age_s` | chain-seconds since the finalized checkpoint | 🟡 not alone |
| 5 | `diff` | tip block's PoW difficulty | 🟢 never |
| 6 | `peers` | live peer count | ⛔ **not documented — issue #172 open, see §6** |
| 7 | `mempool` | pending transactions | 🟢 never |
| 8 | `epoch` | committee epoch | 🟢 never |
| 9 | `regime` | Final / Degraded / Halting / Halted | 🟡 not alone |
| 10 | `halt` | this release's scheduled halt height | 🟡 not alone (cross-host) |
| 11 | `hignore` | blocks not acted on because this release halted | 🟡 not alone |
| 12 | `powrej` | headers rejected for failing the PoW target | 🟡 not alone |
| 13 | `dialable` | `<dialable>/<known>` addresses in the address book | 🟡 not alone |
| 14 | `rounds` | **live** checkpoint rounds closed since process start | 🟢 never |
| 15 | `rfail` | live rounds closed without finalizing | 🟡 not alone |
| 16 | `fid` | identity of the finalized checkpoint | 🟡 not alone — **the comparison is the R2 STOP, and it is only a comparison at equal `final=`** |
| 17 | `sslot` | slot this node's own keys last committed to | 🟢 never |
| 18 | `sid` | identity those keys committed to, or `split` | 🔴 **yes — `sid=split`** |
| 19 | `rback` | slots this node crossed as **history** | 🟢 **never. This is the field that cost two reports.** |
| 20 | `stip` | height whose **body** the state machine applied | 🟢 never |
| 21 | `slag` | `tip − stip` | 🟡 not alone — **the slope is the reading, not the value** |
| 22 | `uanchor` | bodies neither applied nor charged for | 🟡 not alone |
| 23 | `mready` | mining-readiness verdict | 🟢 never |
| 24 | `stipid` | identity of the applied tip | 🟡 not alone |
| 25 | `schain` | `main` / `fork` / `-` | 🔴 **yes — `schain=fork`** |
| 26 | `breq` | historical block-body requests in flight | 🟡 not alone |
| 27 | `fback` | ⛔ **not documented here** — appended 2026-08-01 by `issue #85` | — |
| 28 | `prest` | committee punishments restored at process start | 🟡 not alone |
| 29 | `uex` | ⛔ **not documented here** — appended 2026-08-01 by `issue #200` | — |
| 30 | `bdrop` | `<total>@<height>` — bodies the state machine refused, and where | 🟡 not alone — **read the height against `stip=`** |
| 31 | `unk` | `<frames>/<inv items>` this build does not implement | 🟡 not alone — see §31 |

⚠️ **Two fields on the line still have no section here: `fback=` and `uex=`.** It is named above
rather than omitted so that an operator meeting it cold knows it is
*undocumented*, not *unknown to this project* — the exact distinction the `rback=`
failure at the top of this document cost two reports to learn.

⚠️ **The numbering above has now been off by one twice, from the same cause — and the
second time was introduced by the correction of the first.** `#130 (b)` corrected an
off-by-one caused by `fback=` having no row, writing *"a positional reference with a hole
in it points every row after the hole at the wrong field"* — and in the same edit numbered
`bdrop=` **29**, which is wrong, because `uex=` (`issue #200`) sits between `prest=` and
`bdrop=` on the real line and also had no row. `bdrop=` is **30**.

**Corrected here by giving every field on the line a row, undocumented ones included** —
a hole is what breaks this index, so the fix is to have none rather than to renumber
around them. The order is checked against the format string in `qumbra-node/src/run.rs`,
which is the authority: `breq fback prest uex bdrop unk`.

---

# Part 1 — the fields that have already cost someone time

## 1. `rback` — slots this node crossed as history

**🟢 Never an alarm on its own. Not under any value.**

**What it counts.** Checkpoint slots that closed at this node having been reached
as *history* rather than as a round it could have participated in
(`RoundLedger::backfill_total`, `crates/qlab-node/src/round.rs:948`). The
classifying rule is `is_live_slot(height, tip)`: a slot is **live** if it is
within one checkpoint cadence (8 blocks) of this node's own fork-choice tip *at
the moment the node first learned of the slot*, and **backfill** otherwise. The
verdict is taken once, at that moment, and never revisited (`round.rs:683`).

The source comment that answers the question directly
(`crates/qumbra-node/src/run.rs:879`):

> `rback=` is appended at the end, under the #87/#84 rule. It exists so the
> narrowing is not indistinguishable from deleting the counter on the line an
> operator actually reads: the history a node walked through is a real fact (**it
> is the #104/#106 restart signature**), **it is just not a failure.**

and from the ledger itself (`round.rs:944`):

> A large value beside a small `rfail` is the signature of a node that restarted
> and caught up, which is a fact worth having **and not an alarm.**

**Normal value.** Small, static, and *different on every host* — that is the
expected state, not a discrepancy. Two shapes are normal:

- **On a host that has never restarted:** a handful, fixed since startup. It
  counts the cadence slots the chain had already run past the first time this
  process's slot cursor ran, which happens whenever a batch of headers lands
  before the first loop pass.
- **On a host that restarted:** climbs from 0 immediately after the restart, then
  **stops** and stays fixed. The ceiling is arithmetic, not a health signal: the
  ledger's cursor always restarts at slot 8 (`next_round_slot:
  CHECKPOINT_CADENCE_BLOCKS`, `run.rs:585`) regardless of the height the node
  resumed at, so a node resuming at tip `H` re-walks every slot below `H`,
  classifies all but the last one or two as backfill, and closes them as the
  16-slot open-round cap evicts them. **Expect roughly `H/8 − 1`, then flat.**

**What a change means.** It climbed and then stopped ⇒ this process re-crossed
history it was not present for. On the T0 net that means exactly one thing: it
restarted, or it caught up from a long way behind. It is **the restart signature**
and it is doing its job when it moves.

**A rising `rback` never means anything failed.** A slot counted here is
explicitly excluded from `rounds=` and from `rfail=`
(`RoundDiagnosis::counts_as_a_round`, `round.rs:305`).

**The reading that cost two reports, resolved:**

```
node0   rback=0 → 2 → 6 … later 21      restarted 2026-07-31 14:45Z
node1   rback=4    untouched
node2   rback=4    untouched
node3   rback=4    untouched
```

**This is the expected reading and needs no escalation.** node0 restarted; it
re-walked the cadence grid from slot 8 up to its resumed tip and counted every
slot it crossed as history, which is what the field is for. The three untouched
hosts have not restarted since the mint, so their count has been fixed at 4 since
their first minutes. The two numbers are not comparable, because
**`rback` is cumulative since process start and node0's process is newer than
theirs** (rule 3, §0).

*Basis, and what I did not check:* the arithmetic above is derived from
`run.rs:585`, `round.rs:653` and `round.rs:699`; the observed values are quoted
from `issue #167` and `issue #173`. I have **not** re-run the cursor against
node0's archived log to confirm that its ceiling of 21 corresponds to a first
cursor pass at tip ≈ 165–172, which is what the arithmetic predicts. If someone
wants that closed, it is one grep of `qumbra-ops/node0-restart-0731/after.log`
for the first `ROUND` lines and their `slot=`.

**Escalate when:** never, from this field. If `rback` is climbing and **not**
stopping over many samples, that is a node repeatedly re-crossing history, and the
field to read is `slag=` with `schain=` (§4, §11), not this one.

**Locked by:** `a_catch_up_lands_in_rback_while_a_lost_live_round_still_lands_in_rfail`
(`run.rs:3911`), `a_resync_does_not_manufacture_failed_rounds_but_still_journals_every_slot`
(`round.rs:1361`), `a_backfilled_slot_that_finalizes_here_still_counts_as_a_round`
(`round.rs:1516`).

---

## 2. `rfail` — live rounds that closed without finalizing

**🟡 Not an alarm on its own.** It is the *alarm channel* for a finality stall,
but it says only "a round ended without finalizing", never why. The why is in the
`ROUND` journal on the same stdout stream.

**What it counts.** Live checkpoint rounds — the same population as `rounds=`,
§3 — that closed for any reason other than finalizing
(`RoundLedger::failed_total`, `round.rs:940`). Cumulative since process start.
Backfill slots add nothing here; that was the whole point of `issue #105`.

**Normal value.** `rfail=0` on a net that is finalizing. A steady low number
against a much larger `rounds=` is ordinary — a lost round is not a fault.

**What a change means.** A round this node was a participant in ended without
quorum. Three mechanisms close a round, and they are not equally interesting
(`RoundClose`, `round.rs:208`): `Finalized` (never counted here), `Superseded`
(a later slot finalized first — the catch-up shape), and `Evicted` (the 16-slot
open-round cap pushed it out).

**On the current T0 net, `rfail == rounds` and that is arithmetic, not a fault
in this counter.** The mechanism, end to end:

- Quorum is `FROZEN_QUORUM = 15` of a `FROZEN_COMMITTEE_SIZE = 21` roster
  (`params_devnet.rs:71`, `:75`), and the 21 keys are split 6/5/5/5 across four
  hosts.
- At 13:57Z on 2026-07-31 the journal read `ROUND slot=104 … have=6 need=15
  voted=0,1,2,3,4,5` — **node0's six keys alone against a threshold of 15.**
  (Basis: full non-`-t` container export, 403–409 lines per host, covering
  11:34:05Z–13:59:38Z with no gap; quoted in `issue #165`.)
- 6 < 15, so no round can close as `Finalized`. Each one stays open until 16 newer
  slots have opened, then evicts — so `rounds` and `rfail` climb **in lockstep,
  one per cadence slot, lagging the slot itself by 16 slots (128 blocks).**

So `rfail == rounds` on this net is the correct rendering of "no live round has
finalized here since this process started". **It is not itself the defect, and it
is also not nothing** — it is the downstream symptom of `issue #162`, the wedge
that stops two of the four state machines from reaching the slot at all. The
field is honest; the net is sick. Do not read a stable `rfail == rounds` on the
current T0 net as a new finding.

⚠️ **Two hosts' `rfail` are not comparable if either restarted** (rule 3, §0).

**Escalate when:** `rfail` starts climbing on a net that *was* finalizing. Then
read, in order: `regime=` (§20) and `final=` (§13) to confirm finality actually
stopped, then the `ROUND` lines for `why=` — `silent` (no vote reached us),
`votes_short` (the committee gave all it had), `timeout` (votes still arriving
when it was cut off), `quorum_impossible` (the roster could not have made quorum
however well the network behaved). The `absent=` list on those lines is the
finding.

> **Note for anyone grepping the archived logs:** every log in `qumbra-ops/` is
> captured with `docker logs -t`, which prefixes an RFC3339 timestamp to every
> line, so **any `^`-anchored pattern returns 0 regardless of content.** Use
> `grep -c "ROUND slot="`, never `grep -c "^ROUND"`. A `^ROUND` reading of zero
> was mistaken for a silent journal twice in one day and cost a whole issue
> (`issue #165`).

**Locked by:** `a_live_round_that_genuinely_fails_still_increments_the_alarm`
(`round.rs:1414`), `out_of_window_vote_sets_cannot_pump_the_alarm`
(`round.rs:1469`), `diagnosis_separates_timeout_from_votes_short` (`round.rs:993`).

---

## 3. `rounds` — live checkpoint rounds closed

**🟢 Never an alarm on its own.** It is the *denominator* for `rfail`, nothing
more.

**What it counts.** Rounds this node was a participant in, that have ended
(`RoundLedger::closed_total`, `round.rs:928`) — slots within one cadence of its
own tip when it first learned of them, **plus any round that finalized here
regardless of how it was classified** (`round.rs:838`: hiding a success is the
one direction the filter must never move in). Cumulative since process start.

**Normal value.** Roughly `(blocks produced since this process started) / 8`,
because the checkpoint cadence is 8 blocks (`CHECKPOINT_CADENCE_BLOCKS`,
`params_devnet.rs:94`) and a round only closes once its outcome is settled. At the
75 s target block time that is about one round every 10 minutes; measured WAN
pacing over the 48 h soak was mean 86 s / median 60 s per block (1,707 intervals,
PR #93), so ~7–12 minutes per round in practice.

**What a change means.** `rounds` **not** advancing while `tip=` climbs means no
round is closing — either nothing is finalizing (rounds stay open until the cap
evicts them, which is a 16-slot delay) or this node is crossing every slot as
history (see `rback`, §1). `rounds` advancing with `rfail` flat is the healthy
picture.

**`rounds=0 rfail=0` on a young or freshly restarted process is normal**, not a
silent instrument: the first round cannot close until it either finalizes or is
evicted by 16 later slots.

**Escalate when:** never from this field alone. Use it to size `rfail`.

**Locked by:** `open_is_not_a_closed_verdict` (`round.rs:1201`),
`open_rounds_are_capped_and_evictions_are_reported` (`round.rs:1135`),
`genesis_is_never_journalled_as_a_round` (`round.rs:1089`),
`round_journal_volume_is_set_by_the_cadence_not_the_block_rate` (`run.rs:4115`).

---

## 4. `slag` — how far the state machine trails its own chain

**🟡 Not an alarm on its own — and the value is the wrong thing to read.**
**The slope is the reading.** Read it with `schain=` (§11), always.

**What it counts.** `tip − stip`: the number of blocks whose **headers** fork
choice holds but whose **bodies** the state machine has not applied
(`StateLag::blocks`, `crates/qlab-node/src/telemetry.rs:140`). Measured
saturating, so it can never underflow; `slag=0` means the two views agree and is
the healthy reading. Always printed, zero included.

**Normal value.** `slag=0`. A brief nonzero during catch-up is expected.

**What a change means — the slope, not the value.** From the production
measurement on 2026-07-31 (`issue #162`, `slag` sampled once a minute on four
hosts):

```
19:37  n1=0  n2=3   n3=3
19:39  n1=0  n2=7   n3=7
19:42  n1=0  n2=9   n3=9
19:44  n1=2  n2=10  n3=10
19:45  n1=3  n2=11  n3=11
19:47  n1=4  n2=12  n3=12
19:49  n1=5  n2=13  n3=13
```

node2/node3: **+10 over 12 minutes = 0.83 blocks/minute**, against a target block
rate of one per 75 s = 0.80 blocks/minute (`POW_TARGET_BLOCK_TIME_SECS`, FROZEN).

**A `slag` slope equal to the block rate means the state machine applied *zero*
blocks in that window.** The lag is growing purely because the chain moved. A node
that is genuinely catching up, however slowly, has a slope strictly *below* the
block rate; a node that is keeping up has a slope of zero.

So the two readings an operator must separate are:

| reading | verdict |
|---|---|
| `slag` large, slope < block rate | catching up. Wait. |
| `slag` large, slope ≈ block rate | applying nothing. This is the wedge shape. Read `schain=`. |

*Basis: 7 samples over 12 minutes on two hosts, one-minute sampling, 2026-07-31
T0 WAN net, quoted from `issue #162`. The block-rate comparison uses the frozen 75
s target, not a measured interval over that same window — the measured WAN mean
over the 48 h soak was 86 s (1,707 intervals, PR #93), which would make the ratio
slightly **higher** than 1.0 and does not change the conclusion.*

**What `slag` alone cannot tell you** is whether the state machine is behind on
the same chain or stranded on a different one. That is `schain=` (§11), and the
two have opposite operator responses.

**Escalate when:** `slag` is nonzero and its slope tracks the block rate over
several samples, **or** `schain=fork` (which is 🔴 on its own). Note that a lagging
node also refuses its duties — it will not mine and will not admit a transaction —
so a nonzero `slag` is already suppressing work quietly.

**Locked by:** `a_node_behind_its_own_chain_says_so_on_the_telemetry_line_and_refuses_to_mine`
(`run.rs:1987`), `state_lag_never_underflows_and_zero_is_not_lagging`
(`telemetry.rs:1017`), `supply_coverage_and_state_lag_are_the_same_comparison`
(`telemetry.rs:966`), `i162_a_state_machine_on_a_losing_sibling_never_rejoins_the_main_chain`
(`crates/qlab-p2p/src/adapter.rs:1808`).

---

## 5. `stip` — the height the state machine has applied

**🟢 Never an alarm on its own.**

**What it counts.** The highest height whose **body** the state machine has
applied to state (`StateLag::state_tip`). `tip=` has always been fork choice —
what headers this node has chosen — and these are two different views that a node
holds simultaneously and that can disagree permanently (`issue #130`).

**Normal value.** `stip == tip`, i.e. `slag=0`.

**What a change means.** `stip` frozen while `tip` climbs is the wedge. Read
`slag=` for the size and `schain=` for the verdict.

**🔴 `stip` publishes a height and not an identity.** Two hosts printing `stip=1`
may be on *different blocks at height 1* — that is exactly what happened on the
2026-07-31 T0 net, where node2's applied block at height 1 was a sibling on a
losing branch and separating it from node0's cost an archive dive. **Never
conclude two hosts agree from `stip` alone**; that is what `stipid=` (§10) is for.

**Escalate when:** never from this field alone.

**Locked by:** `nodes_at_one_stip_height_on_different_applied_blocks_print_different_stipid`
(`run.rs:2131`), `the_lag_and_the_branch_are_orthogonal` (`telemetry.rs:1095`).

---

## 6. `peers` — ⛔ deliberately not documented

**This row is missing on purpose, and its absence is the point.**

`peers=` is `t.peer_count`, taken from `P2pNode::peers().len()` — the size of the
`PeerTable` (`crates/qlab-p2p/src/peer.rs:146`), which is a live registration
count and is **distinct from** the `dialable=<n>/<n>` pair, which reports the
address book (§17).

Beyond that, **what the number should be on an N-host mesh, and whether a peer
can remain counted after its connection is gone, are open questions in
[`issue #172`](https://github.com/qumbra-labs/qumbra-lab/issues/172)** — filed on
2026-08-01 after a restarted host read `peers=6` for eight hours while its three
untouched peers read `peers=8`. #172 states the two candidate causes have
**opposite fixes**, and that it does not yet know which of 6 or 8 is the correct
number for a four-host mesh — so the framing of which hosts are anomalous may
itself be backwards.

A row here would have to pick one of those readings. **A wrong row is worse than
a missing one**, because an operator would act on it and the missing one is
visible. This section will be written when #172 lands.

**Until then:** a cross-host `peers=` discrepancy is a **known, undiagnosed
condition** — report it against #172, do not treat it as a new finding, and do
not infer connectivity health from the number in either direction.

---

## 7. `sslot` — the slot this node's own keys last committed to

**🟢 Never an alarm on its own.**

**What it counts.** The highest checkpoint slot any committee key held by *this
node* has committed to, read from the never-double-sign ledgers
(`LocalCommitment::slot`, `telemetry.rs:82`) — the same records that live in
`finalizer-*.state` and which, before `issue #84`, could only be inspected by
copying those files off the host and hashing them.

It is deliberately **not** the finalized height: at a split, the minority still
finalizes the majority's checkpoint, so the two agree on `final=` and differ only
here.

**Normal value.** On a key-holding node: on or near the cadence grid, close
behind `tip`. On a verify-only node holding no committee keys: `sslot=- sid=-`,
and that is correct, not a gap.

**What a change means.** `sslot` not advancing while `tip` climbs past cadence
slots means this node's keys have stopped signing. On the 2026-07-31 net that is
exactly what node2 and node3 showed (`sslot=0` while `tip=14`): their state
machines never reached the slot, so they were **absent from it**, which is a
different failure from disagreeing about it.

**`sslot` leads `final=`, and that is what makes a `fid` split readable.** A key
commits at **sign** time; `fid` only moves once a quorum is recorded finalized.
So a host mid-transition prints an `sslot` **above** its own `final=`, carrying
the identity the rest of the net is about to agree on. A host whose `sslot`/`sid`
match the leader's height and identity while its `fid` still names the older
checkpoint is **behind by one propagation step, not diverging** — §9 step 4. On
the `t0-wan-5` roll (2026-08-01 12:52) that is exactly what node2 showed:
`sslot=800 sid=17dd2cbdac3a` while its own `fid` still read the `792` checkpoint
(`issue #183`).

**Escalate when:** never from this field alone. Read it beside `sid` (§8) and
`stip`/`slag` (§4, §5) — a stuck `sslot` with a stuck `stip` is the state machine,
not the committee.

**Locked by:** `a_node_with_no_keys_prints_the_absent_sentinel` (`round.rs:1311`),
`a_guard_refused_slot_still_names_what_this_node_is_committed_to`
(`round.rs:1327`), `a_recorded_commitment_is_never_un_set` (`round.rs:1339`).

---

## 8. `sid` — the identity this node's keys are committed to

**🔴 YES — `sid=split` is an alarm on its own.** Every other value is 🟡.

**What it counts.** The checkpoint identity that every key held by this node
agrees on at slot `sslot`, as 12 lowercase hex characters — or the literal token
`split` when this node's own held keys are committed to **different** checkpoints
at one slot (`LocalCommitment::id_field`, `telemetry.rs:99`). `-` when the node
holds no keys or has committed to nothing.

**`sid=split` is this node equivocating against itself across its own key set.**
It is reachable: a key restored from a ledger written on one history refuses to
re-sign while a key with no ledger signs the new one. Printing one of the two
identities instead would be exactly the failure `issue #84` exists to remove — a
line that looks healthy while the thing it describes is not.

**Normal value.** A 12-hex identity, or `-` on a verify-only node.

**What a change means, and the distinction that matters:**

| observation | verdict |
|---|---|
| `sid=split` on one host | 🔴 **alarm.** That host's key set disagrees with itself. |
| `sid` differs **across hosts** at the same `sslot` | a **finding**, not a stop — this is the half that catches a committee split, and it may also simply mean a host was absent from the slot. |
| `sid` differs across hosts at **different** `sslot` | **not a disagreement about content** — the two hosts are committed at different slots, so the identities are not comparable. Judge `sslot` itself first (§7: a host whose `sslot` is stuck while `tip` climbs has stopped signing, which is the `issue #162` shape), and compare identities only at a shared slot. |
| `fid` differs across hosts at the same `final` | 🔴 **R2 STOP** — see §9. |
| `fid` differs across hosts at **different** `final` | **not R2** — one host is ahead. §9 step 1. |

The `fid` rows are kept apart from the `sid` rows deliberately: a `fid` split **at
one height** is a STOP and a `sid` split is a finding. On the 2026-07-31 net, node2/node3 printed a different `sid`
from node0/node1 and that turned out **not** to be a committee split on content
at all — they had not signed at that slot at all, because their state machines
never reached it (`issue #162`). Check `sslot` before concluding anything from a
cross-host `sid` difference.

**Escalate when:** `sid=split` on any host, immediately. A cross-host `sid`
difference: report it with the `sslot` values beside it.

**Locked by:** `a_split_round_is_one_grep_across_the_hosts` (`round.rs:1275`),
`identity_fields_are_present_and_well_formed_before_anything_finalizes`
(`run.rs:3679`).

---

## 9. `fid` — the identity of the finalized checkpoint

**🟡 Not an alarm on its own — but the cross-host comparison is the one R2 STOP
this line can express. Compare the heights before the identities.**

**What it counts.** The identity of the checkpoint at `final=`, as 12 lowercase
hex characters, read from the finality tracker's own head — the checkpoint the
quorum was verified against, not a re-derivation (`run.rs:711`). `-` when nothing
is finalized.

**Why the field exists.** `final=` says how high, never **what**. Until `issue
#84` landed, two nodes that finalized *different* checkpoints at the same height
printed identical telemetry — **the most severe consensus failure this net can
have was invisible to the only instrument an operator has.**

**Normal value.** Identical across every host that reports the **same** `final=`.
Across hosts reporting **different** `final=`, a differing `fid=` is the ordinary
state, not a discrepancy: `fid` names a different checkpoint because it is a
different height.

### 🔴 The comparison, in order. Step 1 is not optional.

**1 — Compare `final=` first.** **Different heights ⇒ not a fork**, whatever the
`fid=` values say. One host is ahead and the other has not recorded that
checkpoint finalized yet; finality propagates. This is not R2, and it is not an
escalation. Go to step 3.

**2 — Only when `final=` is equal across hosts does `fid=` decide anything.**

```
same final=       +  different fid=   ⇒  two different checkpoints at one height  ⇒  🔴 R2 STOP
different final=  +  different fid=   ⇒  one host is ahead                        ⇒  not R2 — step 3
```

**The R2 stop-point is the first line of that block and this section narrows
nothing about it**: two hosts reporting one `final=` and two `fid=` values is a
STOP on the first sample that shows it — no waiting period, no second opinion, no
corroborating field. Everything below concerns the case where the heights
**differ**, which was never inside R2's criterion.

**3 — A split at unequal heights should close within a sampling period or two.**
The lagging host's `final=` reaches the leader's and its `fid=` becomes the
leader's value.

⚠️ **Count samples, not seconds.** `sample_interval` defaults to 30 s
(`run.rs:599`) but it is a **floor**: the line is emitted from the main loop, and
on the T0 WAN net that loop's period was measured **never below 131 s across 53
samples on four hosts** (`issue #107`, open — the surface named there is
`ratelimit.rs` / `transport.rs` / `addrman.rs`). A "sampling period" is whatever
the gap between two `TELEMETRY` lines on that host actually is.

A split at unequal heights that does **not** close — the lagging host's `final=`
pinned while the leader keeps advancing — is a **finding, and still not R2**:
that host is failing to finalize, which is `regime=` (§20), `rfail=` (§2) and the
`ROUND why=` journal, not a checkpoint disagreement. Report it with both hosts'
`final=`, `fid=`, `sslot=`, `sid=` and the number of samples it has persisted.

**4 — `sslot`/`sid` are the leading indicator, and they are what makes the
reading legible.** A node's keys commit at **sign** time, while `fid` moves only
once a quorum is recorded finalized — so on a host that is mid-transition
`sslot=` runs **ahead** of its own `final=` (§7, §8). A host whose `sslot` is at
the leader's height carrying the leader's `sid`, while its own `fid` still names
the older checkpoint, **has already signed the thing the others finalized**: it
is mid-transition, not diverging. Read `sslot`/`sid` on both sides before drawing
any conclusion from `fid`.

**The reading this order exists for** (`t0-wan-5` roll, 2026-08-01 12:52,
mid-convergence; four hosts, one sample — `issue #183`, reported by T-ops during
the roll):

```
two hosts   final=792  fid=ff893294bc8a
two hosts   final=800  fid=17dd2cbdac3a
```

**Not R2, and step 1 alone ends it**: 792 and 800 are different heights. The gap
is `800 − 792 = 8`, exactly one checkpoint cadence
(`CHECKPOINT_CADENCE_BLOCKS = 8`) — checkpoints are proposed only on the cadence
grid (`run.rs:1418`), so hosts one checkpoint apart is the smallest disagreement
this field can show and is what a checkpoint in flight looks like. Step 4 says
the same thing from the other side: node2, one of the two hosts printing
`final=792`, was already carrying `sslot=800 sid=17dd2cbdac3a` — it had signed
what the leaders had finalized. It was gone one sampling period later, and
`f800 → f808 → f816 → f824` was unanimous on every tick after.

**Why the order is written down rather than left to judgement.** During ordinary
propagation `fid` differs across hosts constantly, for seconds at a time,
entirely correctly. An operator who has been told only *"a `fid` split is a
STOP"* meets that and escalates — and **an alarm that fires during normal
operation gets turned off.** That is `issue #105`'s lesson (`rounds=1316
rfail=1315` on a healthy node: *"an alarm nobody will ever read again"*), pointed
this time at the most severe alarm the line has. Losing the `fid` check to false
positives would cost more than never having had it.

**What a change means.** `fid` changing on one host while `final=` advances is
ordinary — a new checkpoint has a new identity. `fid` going from a value to `-`
is `final=` going backwards (§13), which is its own 🔴.

**Escalate when:** any two hosts report **the same** `final=` with different
`fid=`. Stop and report per R2; do not restart anything to see whether it
recovers. **Different `final=` is not that condition** — it is step 3: watch it
for a sample or two, and report it only if it fails to close.

**Locked by:** `identity_fields_are_present_and_well_formed_before_anything_finalizes`
(`run.rs:3679`), `telemetry_roundtrips_checkpoint_identity_at_0x04`
(`telemetry.rs:853`).

---

## 10. `stipid` — the identity of the applied tip

**🟡 Not an alarm on its own.** It is the identity `stip=` cannot carry.

**What it counts.** The first `CHECKPOINT_ID_BYTES` of the applied block's hash,
rendered through the same helper that prints `fid` and `sid`
(`AppliedTip::id_field`, `telemetry.rs:234`) — so `fid`, `sid` and `stipid` are
three readings of one scheme and are **comparable by eye**. The prefix is taken
directly from the block hash rather than re-hashed, because a second derivation of
one identity presents as "the identities match" while the objects differ.

**Always a value, never `-`.** A node always has an applied tip — genesis at
minimum.

**Normal value.** Identical across hosts that report the same `stip=`.

**What a change means.** Two hosts at the same `stip=` with different `stipid=`
are on **different blocks at the same height** — one of them is on a losing
sibling. This is precisely the condition that cost an archive dive on 2026-07-31
and the reason the field was added (`PR #168`).

**Escalate when:** two hosts share a `stip=` and differ on `stipid=`. Read
`schain=` on both — the one printing `fork` is the stranded one.

**Locked by:** `the_applied_tip_identity_is_the_block_hashs_prefix_at_fids_width`
(`telemetry.rs:1038`),
`nodes_at_one_stip_height_on_different_applied_blocks_print_different_stipid`
(`run.rs:2131`).

---

## 11. `schain` — is the applied tip on the chain this node is following?

**🔴 YES — `schain=fork` is an alarm on its own. Intervene.**

**What it counts.** One comparison, computed in one place
(`AppliedTip::off_main_chain`, `telemetry.rs:245`):

```
state.tip_hash() != chain.main_chain_hash_at(state.tip_height())
```

**Three states, and the third is *cannot judge*:**

| token | meaning | response |
|---|---|---|
| `main` | the applied tip **is** the main-chain block at its height | lagging at worst; it will catch up. Wait. |
| `fork` | it is **not** — the state machine is on a branch fork choice did not choose | 🔴 **it will never catch up. Intervene.** |
| `-` | fork choice holds **no block at all** at the applied height, so the comparison cannot be made | **neither verdict.** See below. |

**Why `fork` is absorbing.** `qlab_node::Node` cannot rewind — `node.rs`'s
`NotExtendingTip`, *"fork/reorg handling is N-later"*. A state machine that has
applied a sibling of the main-chain block at some height has no path back to the
main chain, so `slag=` will grow forever. `slag=13 schain=main` and
`slag=13 schain=fork` print nearly identically and need **opposite** operator
responses; that separation is the whole requirement this field was built to meet.

**Why `-` must not render as either verdict.** A node whose fork choice holds no
block at its own applied height cannot answer the question. Collapsing that into
`main` would report health on the absence of evidence, and collapsing it into
`fork` would fire an alarm on the absence of evidence. Both are worse than saying
so. The code takes the same position twice, in opposite directions, and the
asymmetry is deliberate: `off_main_chain()` returns `Option<bool>` and preserves
the third answer for anything that renders it, while `is_off_main_chain()` — the
plain predicate an alarm keys on — maps the unknown to `false`, because **an alarm
must not fire on the absence of evidence** (`telemetry.rs:249`).

`-` is unreachable while fork choice is at or above the applied tip, which is
every node in a healthy or a lagging state. If you ever see it, that is itself
worth reporting: it means a node applied a block at a height its own fork choice
does not have.

**Normal value.** `main`.

**Reading it with `slag=`:** `slag=0 schain=main` healthy · `slag=13 schain=main`
catching up, wait · `slag=13 schain=fork` **wedged, intervene** · `schain=-`
report it.

**Escalate when:** `schain=fork` on any host, or `schain=-` on any host.

**Locked by:** `the_wedge_verdict_separates_lagging_from_stranded_and_refuses_to_guess`
(`telemetry.rs:1061`), `the_lag_and_the_branch_are_orthogonal`
(`telemetry.rs:1095`).

---

# Part 2 — the rest of the line

## 12. `tip` — fork-choice tip height

**🟢 Never an alarm on its own.**

**What it counts.** The height of the header chain this node has chosen. This is
fork choice, and it is **not** the same as what the node has applied (`stip=`,
§5) or finalized (`final=`, §13).

**Normal value.** Climbing at roughly one block per 75 s
(`POW_TARGET_BLOCK_TIME_SECS`, FROZEN). Measured at real WAN pacing over the 48 h
soak: mean 86 s, median 60 s, p99 320 s across 1,707 intervals (PR #93) —
ordinary PoW variance, not a defect. Hosts stay within a block or two of each
other; the same soak recorded all four ending at the same `final`.

**What a change means.** `tip` not advancing on **all** hosts is mining stopping.
`tip` not advancing on **one** host is that host being disconnected or refusing to
extend (check `mready=`, §25). A `tip` that goes backwards is a reorg.

**Escalate when:** never from this value alone; but `tip` frozen across all hosts
for many samples is a net-wide stop and worth reporting.

---

## 13. `final` — the finalized head height

**🔴 YES — a `final=` that goes backwards is an alarm on its own, and that
includes `N` → `-`.**

**What it counts.** The height of the finalized head, or `-` when nothing is
finalized (`run.rs:838`). Genesis is finalized at startup as a bootstrap act, so a
fresh net reads `final=0` — not `-`.

**Normal value.** Advancing on the cadence grid (multiples of 8), identical
across hosts, trailing `tip` by less than 16.

**🔴 The alarm.** R2's first criterion is *"finality regressing (a `final=` that
goes backwards on any node)"*. **`0` → `-` is a `final=` that went backwards** —
that reading, on node0 after a restart on 2026-07-31 while its three peers still
held `final=0`, was correctly filed as R2 (`issue #167`) and the underlying defect
was real (`issue #169`: `restore_from_snapshot` dropped the finalized head;
fixed in `PR #171`).

**`final=0` on a net that has never finalized anything above genesis is NOT this
alarm.** That is the current T0 net's known state (`issue #162`). The alarm is the
*transition* backwards, on one host, relative to what that host previously
printed or what its peers print.

**What a change means.** Not advancing while `tip` climbs ⇒ a finality stall ⇒
`regime` will read `Degraded` once the gap exceeds 16. See `rfail` (§2) for the
alarm channel and the `ROUND` journal for the cause.

**Escalate when:** `final=` decreases, or becomes `-` having been a number, on any
host. Stop and report per R2. Do not restart to see whether it recovers.

**Locked by:** `starts_mines_checkpoints_and_persists` (`run.rs:1730`).

---

## 14. `stall` — `tip − final`

**🟢 Never an alarm on its own.** It is `regime=` in another unit.

**What it counts.** `tip − final`, or `tip` when nothing is finalized
(`Telemetry::assemble_with_halt`, `telemetry.rs:410`). Note the second case: on a
net with nothing finalized, `stall` **is** the tip height, so a large `stall`
there carries no information beyond "nothing has finalized".

**Normal value.** ≤ 16 (`DEGRADED_MODE_LAG_BLOCKS = 2 × CHECKPOINT_CADENCE_BLOCKS`,
`params_devnet.rs:137`, FROZEN). At exactly the threshold the regime is still
`Final`; above it, `Degraded`.

**What a change means.** Crossing 16 is the same event as `regime` flipping to
`Degraded`. Nothing more.

**Escalate when:** never from this field alone.

---

## 15. `age_s` — chain-seconds since the finalized checkpoint

**🟡 Not an alarm on its own.**

**What it counts.** Tip block timestamp minus finalized block timestamp — the
same stall as `stall=` but in the unit an operator reasons in ("how long stuck"
rather than "how many blocks behind"). **Chain time, not wall time:** it is
derived from block timestamps and is deterministic given the chain.

**`age_s=-` is not an error and not a zero.** It covers two states in which no
number would be honest (`Telemetry::age_field`, `telemetry.rs:527`): nothing
finalized at all, and the finalized head still being genesis. Genesis is stamped
`timestamp = 0` so that the genesis hash is reproducible, and differencing a
wall-clock tip against it printed the whole Unix epoch — `age_s=1785352360` on
every node of a fresh net, before `issue #73` fixed it.

**Normal value.** Small, on the order of the cadence × block time ≈ 8 × 75 s = 600
s, or `-` on a net that has not finalized above genesis.

**What a change means.** Climbing without bound = a finality stall in seconds.

⚠️ **`stall_depth` and `age_s` are no longer the same stall in two units at cold
start** — a recorded caveat from PR #72; see
`docs/m10-t02-finality-recovery-runbook.md` §2.

**Escalate when:** together with `regime=Degraded` and a climbing `stall`, as the
runbook describes. Not on its own, and never on `-`.

**Locked by:** `telemetry_age_is_dash_when_nothing_finalized` (`run.rs:2318`),
`telemetry_age_is_dash_at_genesis_then_real_after_first_checkpoint`
(`run.rs:2340`), `age_field_is_dash_until_a_real_checkpoint_finalizes`
(`telemetry.rs:740`).

---

## 16. `diff` — the tip block's PoW difficulty

**🟢 Never an alarm on its own.**

**What it counts.** The `difficulty` field of the tip header, so the LWMA retarget
trace is visible across a soak. Prints `0` when the tip header is unavailable to
the composition (`run.rs:997`); the wire renders the same absence as `-`.

**Normal value.** Whatever LWMA has converged to for the current hash rate.
`GENESIS_DIFFICULTY` is a `[devnet-placeholder]` (`params_devnet.rs:33`), and the
T0 nets start at `diff=256`.

**What a change means.** A step change means hash rate changed — a miner joined,
left, or a host stopped mining. A `diff` that never moves means LWMA sees constant
solvetimes, which on a `Deterministic` mining clock is an artifact, not a
measurement (that was the whole of `issue #64` item 0).

**Escalate when:** never from this field alone.

---

## 17. `dialable=<n>/<known>` — the address book

**🟡 Not an alarm on its own.** Distinct from `peers=` (§6).

**What it counts.** `<how many known addresses this node has successfully
connected *out* to>/<how many addresses it knows>`
(`AddrMan::dialable_count`/`known_count`, `crates/qlab-p2p/src/addrman.rs:582`).

**"Dialable" means we successfully connected out to it** — not self-reported, not
passively observed. On a net that accepts outbound-only participants, "it
connected to us" proves nothing. The flag is **sticky across disconnect**, because
a partition is not proof of unreachability (`issue #83`).

**Normal value.** `<n>/<n>` — every known address dialable. On the four-host T0
net each host is configured with its three peers, so `3/3` is the expected steady
reading once discovery has settled; **I have not confirmed that against a host
capture** and the address book also learns gossiped addresses, so a larger
denominator is not by itself wrong. Caps: `MAX_OUTBOUND = 8`, `MAX_INBOUND = 32`,
`MAX_ADDR_BOOK = 1024`, `MAX_ADDRS_PER_MSG = 100` (`addrman.rs:63`–`:70`).

**What a change means.** This ratio is the **measured NAT re-open trigger**: if it
collapses toward "only the seeds are dialable", that is the signal to build NAT
traversal — a decision that must fire on a measurement, not on someone's memory
that the question was deferred. `known` climbing while `dialable` stays flat is
exactly that shape.

**Escalate when:** the ratio collapses toward the seed count and stays there.
Report as a NAT-traversal trigger, not as an outage.

**Locked by:** `dialable_is_sticky_across_a_drop` (`addrman.rs:934`),
`only_dialable_addresses_are_gossiped` (`addrman.rs:769`),
`persistence_round_trips_dialable_entries_only` (`addrman.rs:972`).

---

## 18. `mempool` — pending transactions

**🟢 Never an alarm on its own.**

**What it counts.** `node.mempool().len()` — transactions admitted to this node's
pool and not yet in a block.

**Normal value on the T0 net: `0`, permanently.** T1 does not yet allow
transacting — no node in the deployed topology serves note discovery, so no
recipient can find their output (see `CLAUDE.md`, the T1 bullet). A nonzero
`mempool` on a T0 host means either the in-process faucet submitted something or
somebody is gossiping transactions.

**What a change means.** Climbing and not draining = transactions are admitted but
not mined. On a net that transacts, that points at the miner, not the mempool.

**Escalate when:** never from this field alone.

---

## 19. `epoch` — the current committee epoch

**🟢 Never an alarm on its own.**

**What it counts.** `node.committee().current_epoch()` — which committee epoch the
tip height falls in. `EPOCH_LENGTH_BLOCKS = 1_152` (`params_devnet.rs:82`), so
epoch `N` begins at height `N × 1152`.

**Normal value.** `tip / 1152`, identical across hosts except transiently at a
boundary.

**What a change means.** An increment is the scheduled boundary crossing, and it
is **not** instantaneous across hosts. Measured at real WAN pacing over the 48 h
soak (PR #93): epoch 0→1 at `tip=1152` with all four hosts within **28 s**, and
1→2 at `tip=2304` within **79 s**. A brief cross-host disagreement in `epoch` at
those heights is normal.

**What to watch at a boundary, though not from this field:** two nodes that
disagree about a tombstone read each other's honest votes as forged **at the next
epoch boundary, not before** (`issue #164`, open). If finality breaks *exactly*
when `epoch` increments, say so in the report — that is a named open defect.

**Escalate when:** never from this field alone; hosts disagreeing on `epoch` far
from a boundary means their `tip` disagrees, which is a `tip` question.

---

## 20. `regime` — the finality regime

**🟡 Not an alarm on its own. `Degraded` is a designed state, not a failure.**

**What it counts.** One of four tokens, derived once for the whole stack
(`qlab_devnet::halt::regime`) and never re-defined by telemetry:

| token | rule |
|---|---|
| `Final` | something is finalized and `tip − final ≤ 16` |
| `Degraded` | nothing finalized yet, **or** `tip − final > 16` |
| `Halting` | `tip` has reached this release's halt height `H`, but `H` has not finalized yet |
| `Halted` | `H` is finalized — everything pre-halt is final by construction, and it is now safe to swap binaries |

**`Degraded` means the PoW chain keeps producing blocks in probabilistic mode
while the committee has no fresh finality. Liveness is never hostage to the
committee.** This is frozen §4 Ebb-and-Flow behaviour and a stall on its own is
safe. The failure mode the design exists to avoid was not the stall; it was having
no designed way to recover from one.

**Normal value.** `Final`. The 135-minute docker soak recorded `regime=Final`
in 107 of 108 samples.

**What a change means.** `Final` → `Degraded` = finality stopped or the gap grew
past 16. `Degraded` staying put across a long window is a stall; the runbook
(`docs/m10-t02-finality-recovery-runbook.md`) is the procedure.

**`Halting` that does not become `Halted` is a reason *not* to swap binaries
yet** — it is the honest outcome of finality failing to close at the boundary.

**Escalate when:** `Degraded` persists — with `stall`, `age_s`, `rfail` and the
`ROUND why=` lines in the report. Not on the first sample.

**Locked by:** `telemetry_roundtrips_both_regimes` (`telemetry.rs:713`),
`telemetry_roundtrips_halting_and_halted` (`telemetry.rs:760`).

---

## 21. `halt` — this release's scheduled halt height

**🟡 Not an alarm on its own — but a cross-host difference is.**

**What it counts.** The halt height this **binary** is compiled with, or `-` when
this release schedules none (`run.rs:847`). It comes from the compile-time
`RELEASE` constant; nothing in the config file, the CLI or the environment can
reach it.

**Normal value.** `-` outside an upgrade drill; the announced height during one,
**identical on every host**.

**What a change means.** It cannot change within a process. Two hosts printing
different `halt=` values means **they are running different images** — which is
worth knowing before anything else on the line is compared, since a mixed-image
net explains a great many other discrepancies.

Combined with `regime=`, it separates "paused at the announced boundary"
(`regime=Halting`/`Halted` at `tip == halt`) from "stuck" (`regime=Degraded` with
no halt in sight). A cancelled release names its stand-down height for audit but
halts nowhere, so `halt=-` while an upgrade was announced is a legitimate reading.

**Escalate when:** hosts disagree on `halt=`. Report the image digests with it.

**Locked by:** `armed_release_halts_at_h_and_writes_a_durable_marker`
(`run.rs:3018`), `drill_d_cancelled_release_mines_through_the_cancelled_height`
(`run.rs:3453`), `halt_default_schedule_is_a_no_op` (`adapter.rs:3423`).

---

## 22. `hignore` — blocks not acted on because this release is halted

**🟡 Not an alarm on its own.**

**What it counts.** Headers/blocks this node did **not** act on because its own
release is halted — attributed to the **RELEASE** layer, with **no fault charged
to the sender** (`IngestCounters::halt_ignored`, `adapter.rs:317`). A peer still
mining above the boundary is on a different release, which the governance design
permits. Cumulative since process start.

**Normal value.** `0` outside an upgrade drill.

**What a change means.** During a drill, a climbing `hignore` is the drill
working: the old branch is being ignored at the release layer rather than rejected
as invalid. **Nonzero `hignore` with `halt=-` should not be possible**; if you see
it, report it.

The pair with `powrej` answers the drill's whole question — *which layer rejected
the old branch?* — from two numbers rather than from a narrative.

**Escalate when:** nonzero while `halt=-`.

**Locked by:** `halt_stops_mining_accepting_and_signing_above_h` (`adapter.rs:3440`,
which asserts `halt_ignored = 1` and `pow_rejected = 0` for exactly this
attribution), `drill_a_old_miner_grows_past_h_and_never_finalizes`
(`adapter.rs:3523`).

---

## 23. `powrej` — headers rejected for failing the PoW target

**🟡 Not an alarm on its own.**

**What it counts.** Headers whose PoW value did not meet the target — attributed
to the **HEADER-VALIDATION** layer: invalid, not merely unwanted
(`IngestCounters::pow_rejected`, `adapter.rs:320`). Cumulative since process
start.

**Normal value.** `0`, or very small and static.

**What a change means.** Steadily climbing = something is sending headers that do
not meet target. Above an upgrade boundary it is the **post-halt rule domain
biting**, which is the designed behaviour and is what separates it from
`hignore`. Away from a boundary it points at a peer.

**Escalate when:** climbing steadily on a net with no upgrade in progress. Report
the rate with the window it was measured over.

**Locked by:** `halt_stops_mining_accepting_and_signing_above_h` (`adapter.rs:3440`).

---

## 24. `uanchor` — bodies this node could not judge

**🟡 Not an alarm on its own. Read it against `slag=`.**

**What it counts.** Block bodies this node **neither applied nor charged anyone
for**, because it could not evaluate anchor finality from where it stands
(`IngestCounters::unjudged_anchor`, `adapter.rs:328`). Cumulative since process
start; zero is printed rather than omitted.

**This is the joiner's instrument.** Before it existed, a joiner burning its
outbound peer set for serving it *correct* history looked, from the logs, exactly
like "nobody would talk to me" (`issue #134`).

**Normal value.** `0` on an established node.

**What a change means — the pair to read:**

| reading | verdict |
|---|---|
| `uanchor` climbing, `slag` falling | ordinary joining; some bodies deferred, sync progressing |
| `uanchor` climbing, `slag` **pinned** | 🟡 this node is being served history it cannot judge. **Sync is not progressing and the peers are not at fault.** |

**Escalate when:** `uanchor` climbing with `slag` flat over several samples.
Report both numbers with the sample window; do not ban or blame the peers.

**Locked by:** `a_joiner_does_not_fault_a_peer_for_history_it_cannot_judge`
(`adapter.rs:2055`), `the_unjudged_case_is_decided_by_this_nodes_own_two_numbers`
(`adapter.rs:2159`), `a_genuinely_invalid_body_still_costs_the_sender`
(`adapter.rs:2101`).

---

## 25. `mready` — may this node mine right now?

**🟢 Never an alarm on its own.** It exists to *stop* an alarm: **a node
deliberately not mining looked exactly like a node failing to mine**, and until
`issue #106` the operator surface had no field that could tell them apart.

**What it counts.** The mining-readiness verdict (`MineGate`, `run.rs:324`). The
whole gate is one sentence: **before its first block, a node must either know
where the chain is, or know there is no chain to know about.**

| token | meaning | mines? |
|---|---|---|
| `-` | not a miner at all (`mining = false`) | — |
| `synced` | a ready peer claimed a height and this node is not below it | ✅ |
| `alone` | no address to dial and no live peer — this node **is** the net, which is how a brand-new net starts | ✅ |
| `latched` | cleared once already in this process's lifetime | ✅ |
| `unknown` | no ready peer has claimed a height yet, and there are addresses left to try — **the cold-restart state** | ❌ refused |
| `behind` | a peer's chain is taller and this node has not caught up | ❌ refused |

`unknown` and `behind` are the two states node0 was in when it mined a genesis
fork through a restart on the T0 WAN net. **Both refusals are correct behaviour**,
not a fault: the Terraform/security-group failure of Phase B-WAN would have read
`mready=unknown` on all four hosts, which is the whole reason the field exists.

**Normal value.** `synced` or `latched` on a miner; `-` on a non-miner.

**What a change means.** `unknown` at startup is expected and should become
`synced` within a minute or so once the first handshake lands. `unknown` **stuck**
across many samples means no peer is completing a handshake — that is a
connectivity question.

⚠️ **`mready` does not read `slag=`.** On the 2026-07-31 net node2 printed
`mready=synced` and `MINEGATE ready=1 why=synced` while `slag=13`. Whether the
gate is intended to read `slag` at all, or whether these are two independent
readinesses that happen to share a word, is an **open question recorded in
`issue #162`** (observation 1) and is not settled here. **Do not read
`mready=synced` as "this node's state machine is caught up"** — that is `slag=`
and `schain=`.

**Escalate when:** never from this field alone. `unknown` persisting is a
connectivity report.

**Locked by:** `a_cold_node_with_a_taller_peer_does_not_mine_until_it_has_synced`
(`run.rs:2742`), `the_genuinely_first_node_on_a_new_net_does_mine`
(`run.rs:2843`),
`a_node_behind_its_own_chain_says_so_on_the_telemetry_line_and_refuses_to_mine`
(`run.rs:1987`).

---

## 26. `breq` — historical block-body requests currently in flight

**🟡 Not alone.** Pair with `slag=`.

**What it counts.** How many historical block-body asks this node has outstanding
right now (`run.rs` `body_reqs`, capped at `MAX_BODIES_IN_FLIGHT`). Instantaneous
level, not a total — resets implicitly when asks complete. Always printed, zero
included. Appended by issue #130 (c).

**Reading it with `slag=`:** `slag>0 breq=0` is *not asking*; `slag>0 breq>0`
sustained is *asking and not being served*.

**Escalate when:** never from this field alone.

---

## 28. `prest` — committee punishments restored at process start (touches TELEMETRY)

**🟡 Not alone.** A non-zero value is a local fact about this host's ledger; a
cross-host comparison is the load-bearing reading.

**What it counts.** What [`NodeAdapter::open`](../../crates/qlab-p2p/src/adapter.rs)
found in `punishments.dat` and re-applied into the fresh genesis committee on this
process start (`PunishmentRestore::telemetry_field`,
`crates/qlab-p2p/src/punish.rs`). **Latched at open** — every later sample in the
process lifetime reprints the same value. It is a startup fact, not a running total.

**Shape is `restored/known`, not a bare count.** A bare `0` cannot distinguish
*nothing to restore* from *could not restore anything*, and that distinction is
why the field exists:

| value | meaning |
|---|---|
| `0/0` | ledger present (or written empty on this open); nothing to restore |
| `N/M` | `N` tombstones re-applied from `M` on-disk records this process start |
| `unk` | data dir already held chain history but **no** ledger — punishment history is unknowable (pre-#133 datadir). Not silence, not clean. |

⚠️ **A host that has never observed an equivocation prints `prest=0/0` forever.**
That is correct for the local ledger (PR #159) and is **not** proof the net has
never punished anyone. Evidence is push-once gossip with no getdata path: a peer
that saw the conflicting pair and this host did not still disagree about who may
sign, and after a restart they disagree *durably*. Agreement needs the evidence
in blocks (issue #133 D1). Do not "fix" a perpetual `0/0` by deleting the field.

**Normal value.** `0/0` on every host of a net that has never seen an
equivocation — the T0 soak record is exactly that. `N/M` only after this node
itself adjudicated evidence in a prior process lifetime.

**What a change means.** The value cannot change mid-process. A change across a
restart (`0/0` → `1/1`) means this node restored a punishment it had recorded;
that is the healthy PR #159 path. `unk` on first start of a pre-#133 datadir is
the one-shot upgrade signal — an empty ledger is then written so later restarts
are unambiguous.

**Escalate when:** never from this field alone. Two hosts at the same height with
different `prest` (and no shared evidence path) is the class problem D1 names,
not an operator action on one host.

**Locked by:** `telemetry_line_is_extended_at_the_end_and_nowhere_else`
(`run.rs`, expects trailing `prest=0/0`),
`a_committee_punishment_survives_a_restart_through_the_run_path` (`run.rs`,
expects `prest=1/1` after restart),
`a_non_witness_finalizes_a_checkpoint_the_restarted_witness_refuses`
(`adapter.rs` — the two-node same-height divergence the local ledger cannot close).
## 30. `bdrop` — bodies the state machine refused, and where

**🟡 Not an alarm on its own. Read the height against `stip=`.**

**What it counts.** `<total>@<height>`: block bodies this node's own state machine
**refused at the application funnel**, cumulative since process start, paired with
the **chain height of the most recent refusal**. `bdrop=0@-` means none has been
refused; the `-` is the "no figure to state" convention, and it is not the same
claim as a height of `0` (genesis is height 0). See
`NodeAdapter::body_refusals` and `bdrop_field` (`run.rs`).

**Why the field exists.** Until `issue #130 (b)` this refusal was an `Err(_) => {}`
arm under a comment calling the drop expected, and there was no counter and no
field anywhere. **A node dropping every body it was handed printed exactly what a
healthy node prints.** #130 records that this is what made it the worst of five
same-shaped defects that week: *"every other instance was silence; this one was
silence with a comment vouching for it."*

**Why a height and not a rate.** A cumulative total answers *how many* and cannot
answer *are they still arriving*, and those two want opposite responses. One
telemetry line has no previous sample to difference against, and chain time has no
wall-clock anchor here (genesis is stamped `timestamp = 0` for a reproducible
genesis hash — `issue #106`). Height is the monotone quantity that is already on
the line, so the comparison is done by eye from one sample.

**Normal value.** `0@-`.

**What a change means — the pair to read:**

| reading | verdict |
|---|---|
| `bdrop=0@-` | nothing has been refused |
| `bdrop=N@H` with `H` far below `stip=` | a burst that is **over**. Record `N` and `H`; do not escalate on the total alone |
| `bdrop=N@H` with `H` at or next to `stip=` | 🟡 this node is refusing bodies **now**, and `slag=` will not close while it does |
| `N` rising across samples | 🟡 sustained refusal — take the per-reason breakdown from `/metrics` before reporting |

**The per-reason breakdown is on `/metrics`, not on this line:**
`qumbra_body_apply_refused_total{reason=…}` over `not_extending_tip`, `bad_body`,
`nullifier_spent`, `persist_io`, `internal`.

🔴 **Two of those five reasons must be zero forever.**
`reason="not_extending_tip"` and `reason="internal"` are **invariant tripwires**:
the only production caller of `apply_block` selects the body it applies by the
exact negation of the first error's trigger, so a nonzero scrape is a defect in
**this node's own code**, not a network condition. **Report it; it is not an
operator action.** The other three (`bad_body`, `nullifier_spent`, `persist_io`)
can genuinely happen — the first two mean a peer served a chain whose bodies do
not validate, the third is `issue #104`'s shape, a durable chain that has quietly
stopped being durable.

**Escalate when:** `not_extending_tip` or `internal` is nonzero on `/metrics`
(report, do not act); or the total is rising with the height tracking `stip=`
across several samples.

**Locked by:** `a_body_refused_at_the_application_funnel_is_counted_and_located`
and `i130b_a_held_body_that_does_not_extend_the_applied_tip_never_reaches_apply_block`
(`adapter.rs`), `every_apply_failure_classifies_to_a_declared_refusal_reason`
(`qlab-node/src/node.rs`),
`every_body_refusal_reason_is_a_series_from_the_first_scrape`
(`qlab-node/src/metrics.rs`),
`bdrop_renders_the_count_and_the_height_of_the_last_refusal` (`run.rs`).

## 31. `unk` — frames and inventory items this build does not implement

**🟡 Not an alarm alone — and the reading depends entirely on whether an upgrade
is in flight.** It is the version-skew instrument, added by `issue #181` in the
same change that stopped an unrecognised frame from banning its sender.

**What it counts.** `unk=<frames>/<inv items>`, both cumulative **since process
start** (a restart resets them), over traffic that survived the inbound rate
limiter:

- **left** — inbound frames whose *envelope type code* this build does not
  implement. Ignored, never scored;
- **right** — *inventory items* whose kind code this build does not implement,
  over every `inv` / `getdata` / `notfound` received. Skipped, never scored.

Neither number is ever a scoring input. **A peer that appears here has not
misbehaved — it is running a newer build than this host.** Before `#181` such a
frame was charged `PENALTY_MALFORMED` (100) against a `BAN_THRESHOLD` of −100,
i.e. an instant ban on the first frame, which is why no baton has been able to
add a message type since.

**Normal value.** `unk=0/0` on a net where every host runs the same image.

**What a change means.**

| reading | means |
|---|---|
| `0/0` | no skew seen |
| left climbing **during a rolling upgrade** | ✅ expected — this host is older than the one already rolled, and it is coping. It is the *confirmation* that the roll is in progress, not a problem |
| left climbing with **no upgrade in flight** | 🟡 report it. Either a host is running an image nobody recorded, or something is speaking the magic and the version but not the protocol |
| left **stops** climbing after a roll completes | ✅ the skew closed |
| right climbing | the same thing one layer in — a peer is offering an inventory kind this build has no code for |

🔴 **The sequencing this field exists to make visible, and it is the whole point
of `#181`: the fix only helps for versions AFTER it lands.** Every host must be
running the `#181` image before any new `MsgType` or `InvKind` may be introduced.
A host that predates it still bans on the first unknown frame — and it will not
print `unk=` at all, because it does not have the field. **An absent `unk=` is
therefore itself a reading: that host is not yet safe to send a new type to.**

⚠️ **`unk` does not cover a `PROTOCOL_VERSION` bump.** A frame at a version this
build does not speak is still scored as malformed and still bans on the first
frame. `#181` deliberately did not move that (a version bump is a wire break, not
an additive change) and recorded it as open. Do not read `unk=0/0` as "any wire
change is safe to roll".

**On `/metrics`** as `qumbra_unknown_msg_type_total` and
`qumbra_unknown_inv_kind_total`, the same two numbers. There is also a `WIRE`
journal line naming each distinct unknown type code the **first** time it is
seen (`WIRE event=unknown_type type=0x0044 … action=ignored scored=no`), capped
at 8 distinct codes per process so it cannot itself be flooded — the count keeps
going after that, only the narration stops.

**Escalate when:** never from this field alone. Report a climbing left-hand
number when no upgrade is in flight.

**Locked by:** `an_unknown_envelope_type_is_ignored_and_never_scored` and
`a_malformed_body_under_a_known_type_is_still_penalised`
(`crates/qlab-p2p/src/node.rs`),
`an_unknown_envelope_type_over_tcp_is_ignored_and_reported_on_both_surfaces`
(`crates/qumbra-node/src/run.rs`).

---

## 32. `bask` — the ask set, and where the requester is walking from (issue #229)

**🟡 Not alone.** Pair with `breq=` (§26), `slag=` (§4) and `schain=` (§11).

**What it says.** Two numbers, `<ask set>@<fork point>`:

- **the ask set** — how many main-chain block bodies
  [`missing_body_hashes`](../crates/qlab-p2p/src/adapter.rs) produced on this
  sample. **This is not `breq=`.** `breq=` is how many asks are *in flight*;
  `bask=`'s first number is how many the requester *wanted*.
- **the fork point** — `state_fork_point()`'s answer: the highest block this
  node has applied that is *also* on the chain fork choice is following, or `-`
  if the walk produced nothing. It is where the requester starts asking from, and
  before this field no surface published it.

**Caliper.** Instantaneous, computed at print time, with the same `max` the
requester itself uses (`MAX_BODIES_IN_FLIGHT` = 16) — **so the first number
saturates at 16 and is not a gap size.** Use `slag=` for the gap. Always printed,
`0@-` included.

**Normal value.** `bask=0@<stip>` on a healthy node: nothing to fetch, and the
fork point is the applied tip because the applied tip is on the main chain. A node
that is legitimately catching up shows a nonzero first number that falls.

**Why it exists.** On 2026-08-03 three hosts printed `schain=fork`, a frozen
`stip`, `slag=21` and `breq=1–2` for over an hour, and the diagnosis turned on a
number none of those four fields carried: **an ask set of 15 with 2 in flight and
an ask set of 2 are the same `breq=` and different bugs.**

| reading | what it means |
|---|---|
| `bask=15@2680 breq=15` | the requester is doing its job — a **serving** problem, read the `BODYWAIT` entries |
| `bask=2@2680 slag=21` | the ask set cannot close the gap it is looking at — a **requester** problem |
| `bask=0@-` | `state_fork_point()` answered nothing; the requester has no base |

**The detail is on the `BODYWAIT` journal line, not here.** When a node's `stip`
has not moved for `UNOBTAINABLE_BODY_CADENCES` cadences (20 minutes at the frozen
75 s block time) and it is either off-main or still asking, `qumbra-node` writes
to stdout:

```
BODYWAIT stip= stipid= schain= slag= sfork= ask= breq= pend= gate= mine= mrefuse= stuck_s=
BODYWAIT ask h= id= age_s= asks= flight= ans=<peer>:<served|header-only|dont-have|noreply>,…
```

- `gate=` is `rejoin_main_chain`'s own condition, evaluated without taking it:
  `missing@N` means this node does **not** hold the main-chain body at `fork + 1`,
  so the rewind that would rejoin the chain will not be taken.
- `pend=` is the pending-body window's occupancy. **`pend` climbing with
  `gate=missing` is bodies arriving that do not help.**
- `mine=refused-lag` with `mrefuse=N` is **this node has stopped mining** — the
  duty gate declining because its applied view is stale. It is correct behaviour
  and it was previously visible only as a `/metrics` counter on hosts that expose
  no metrics endpoint.
- `ans=` names **every peer the ask went to**, including the ones that said
  nothing (`noreply`). `header-only` is a peer that holds the header and not the
  body — the honest answer of any node that restarted, because the serving cache
  is not persisted.

A full report is written when the picture changes and a summary on a heartbeat
while it does not; a healthy node, and a node merely behind with `stip` advancing,
write **nothing**.

**Escalate when:** never from this field alone. `bask=` disagreeing with `slag=`
by an order of magnitude on a host that is also `schain=fork` is a finding worth
reporting with the `BODYWAIT` lines attached.

**Locked by:** `bask_publishes_the_ask_set_and_the_fork_point_which_breq_cannot`
and `a_stranded_node_journals_what_it_wants_and_that_it_has_stopped_mining`
(`crates/qumbra-node/src/run.rs`),
`the_three_layers_do_not_print_the_same_line` and
`a_healthy_node_and_a_node_merely_behind_emit_nothing`
(`crates/qlab-p2p/tests/ask_set_observable.rs`).

⚠️ **This document's field list in §0 is stale and `bask` is not the reason.**
`cpq`, `dfin` and `fdrop` (issue #204) were appended before this field and were
never added to it. Read the `format!` in `run.rs` as the authority, as §0 already
tells you to. *(`dfin` now has a section — §33 — because issue #212 gave it a
companion. `cpq` and `fdrop` still do not.)*

---

## 33. `dfin` / `dfinbh` — the finalized head that survives a restart (issue #212)

**🔴 `dfinbh` differing between hosts at one `dfin` is a STOP. 🟡 `dfin` differing
from `final=` on one host is not.** Read this section before acting on either.

**What they say.** **Head #3** — the state machine's chain store. This is the
finalized head [`Snapshot.finalized`](../crates/qlab-node/src/persist.rs) is
written from, the head the no-reorg-past-finality rule executes on, and **the only
finalized head that survives a restart.**

- **`dfin`** — head #3's height, or `-` when it holds nothing.
- **`dfinbh`** — the identity of the **block** head #3 holds at that height: the
  first 6 bytes of its block hash, or `-`.

**🔴 `final=` and `fid=` (§13, §9) are a different head.** They read the committee
`FinalityTracker` — **head #1** — which needs only a quorum of votes and is
**discarded at shutdown**. A node can report `final=1056` while a restart would
bring it back at 1048, and on 2026-08-01 node1 did exactly that for hours.

**🔴 `dfinbh` and `fid` are not comparable and lining them up means nothing.**
`fid` is `keccak256(height ‖ block_hash ‖ root)` truncated — the digest of the
exact bytes the committee's ML-DSA keys signed. `dfinbh` is the name of a block. They
are the same width and the same rendering and nothing else. This is the same trap
`OPERATOR.md` §3 records under *"two different values are called 'the genesis
hash'"*, and `dfinbh` is spelled without an `id` so the line itself discourages it.
`dfinbh` belongs beside **`stipid`** (§10), which is a block-hash prefix too.

**Caliper.** Both are instantaneous levels read from the same snapshot the
`/v1/telemetry` wire serves — the line and the wire cannot disagree about them.
Always printed, `-` included.

**Normal value.** `dfin=` equal to `final=`, and `dfinbh=` equal on every host at
that height. That is the reading all four T0 hosts gave at
`2026-08-03 07:11:27Z`: `final=2864 fid=63e42f7e13a7 dfin=2864`, identical field for
field.

| reading | what it means |
|---|---|
| `final=2864 dfin=2864` | healthy — head #1 and head #3 name one block |
| `final=1056 dfin=1048` | 🟡 head #3 has not recorded what head #1 reports. **One sample is a reading, not an alarm** — see below |
| `final=2864 dfin=-` | 🟡 head #3 holds **nothing**: this host returns to genesis on a restart. Report it |
| same `dfin` on two hosts, different `dfinbh` | 🔴 **STOP.** Two hosts durably finalized different blocks at one height |

**Why `dfin` behind `final` is not an alarm on one sample.**
`sync_state_finality` re-attempts on every drain, so the window between a
checkpoint finalizing and its body being applied looks exactly like this. **What is
alarming is *sustained*, and one line cannot establish sustained.** Pair it with
`slag=` (§4 — is the state machine catching up at all?) and `fdrop=` (is the durable
head *refusing* the record?). This is the same call the coordinator made for `cpq=1`
on 2026-08-02: *watch, do not assume.*

**Why `dfinbh` differing IS a stop, and worse than an `fid` split.** An `fid` split
is head #1, which is thrown away at shutdown; this is the head both hosts come back
as. The operator action is the same as row 2 of Appendix A and one step stronger:
**stop, do not roll, preserve the data dir on every host** — the divergence is on
disk, so the evidence survives and rolling would overwrite the binary that produced
it.

**On the wire, and in `qumbra-opview`.** Both fields are on `/v1/telemetry` at
`RPC_VERSION 0x04` and rendered as the `DFIN`/`DFINBH` columns, with the two alarms
on separate verdict lines. `qumbra-opview` exits **2** on a cross-host `dfinbh`
split and **0** on a single host's `final`/`dfin` disagreement, which it reports as
the greppable tokens `DURABLE_LAG`, `DURABLE_ABSENT` and `DURABLE_AHEAD`. A host not
yet rolled onto `0x04` renders `INDETERMINATE` with its wire version — expected
during a roll, not a fault, and every other column on it is still read.

**Escalate when:** two hosts share a `dfin` and differ on `dfinbh` (🔴 immediately);
`dfin=-` on a host reporting a real `final=` (report); `final=`/`dfin=` apart across
several consecutive samples (report, with `slag=` and `fdrop=` attached).

**Locked by:** `the_three_durable_states_are_distinct_on_the_wire_and_round_trip`,
`the_durable_identity_is_a_block_hash_prefix_and_not_a_checkpoint_identity`,
`the_tracker_and_the_durable_head_are_compared_in_one_place`,
`a_reader_at_0x04_still_reads_a_0x03_node_and_knows_that_it_did`
(`crates/qlab-node/src/telemetry.rs`);
`the_2026_08_01_node1_divergence_is_visible_and_was_not_before`,
`two_nodes_durably_holding_different_blocks_at_one_height_is_a_stop`,
`an_unrolled_host_is_indeterminate_with_its_wire_version_not_a_dissenter`,
`the_durable_alarms_render_apart_and_the_view_refuses_the_fid_comparison`
(`crates/qumbra-opview/src`);
`a_durable_split_over_sockets_is_the_stop_condition_while_fid_agrees` and
`a_mid_roll_net_is_fully_readable_over_sockets_and_says_which_hosts_predate_the_field`
(`crates/qumbra-opview/tests/over_http.rs`).

---

## Appendix A — the two-minute triage

In order. Stop at the first 🔴.

1. **`final=` went backwards on any host** (including `N` → `-`) ⇒ 🔴 R2 STOP.
2. **Same `final=`, different `fid=`** across hosts ⇒ 🔴 R2 STOP.
   ⚠️ **Compare `final=` first.** Different `final=` with different `fid=` is
   **not** this row — one host is ahead and finality is propagating. It should
   close within a sampling period or two; if it does not, report it as a finding
   and keep going down this list. See §9, which is the whole check order.
3. **Same `dfin=`, different `dfinbh=`** across hosts ⇒ 🔴 STOP, and **do not roll**
   — the divergence is on disk and rolling overwrites the binary that produced it.
   ⚠️ Same order of operations as row 2: **compare `dfin=` first**, and never
   compare `dfinbh=` against `fid=` — they are different spaces (§33).
4. **`sid=split`** on any host ⇒ 🔴 escalate.
5. **`schain=fork`** on any host ⇒ 🔴 wedged, intervene. (`schain=-` ⇒ report.)
6. `slag` nonzero with a slope ≈ block rate ⇒ the state machine is applying
   nothing.
7. `final=` ahead of `dfin=` on one host, across several samples ⇒ report, with
   `slag=` and `fdrop=`. **One sample is not this row** (§33). `dfin=-` beside a real
   `final=` ⇒ report immediately.
8. `regime=Degraded` persisting ⇒ finality stall; runbook, plus `ROUND why=`.
9. `uanchor` climbing with `slag` pinned ⇒ served history it cannot judge.
10. Everything else ⇒ report with the reading, do not infer.

**Before comparing any counter across hosts**, check whether either host
restarted. `rounds`, `rfail`, `rback`, `hignore`, `powrej` and `uanchor` are all
cumulative since **process** start.

## Appendix B — what this document deliberately does not say

- **`peers=`** — open, `issue #172`. See §6.
- **Whether `mready` should read `slag`** — open, `issue #162` observation 1. See
  §25.
- **`breq=` and `fback=`** — both landed after this document was written and
  neither has a section here. They are named in the glance table so the "in the
  order the line prints them" claim stays true, and nothing more. Do not infer
  their semantics from their names.
- **What a node should do with a `PROTOCOL_VERSION` it does not speak** — open,
  reported by `issue #181`, which fixed the message-type case and deliberately
  left this one. See §26.
- **Any absolute threshold for "too long in `Degraded`"** — there is no measured
  basis for one, and inventing a number here would be exactly the kind of figure
  this project has been bitten by. The runbook owns the procedure.

## Sources

Every row above is derived from one of:
`crates/qumbra-node/src/run.rs` (the render itself, `telemetry_sample`) ·
`crates/qlab-node/src/telemetry.rs` (the shared snapshot and every `*_field`
rendering) · `crates/qlab-node/src/round.rs` (the round ledger) ·
`crates/qlab-p2p/src/adapter.rs` (ingest counters, slot context) ·
`crates/qlab-p2p/src/addrman.rs` (the address book) ·
`crates/qlab-devnet/src/params_devnet.rs` (the frozen constants).

Issues cited: #73 #74 #83 #84 #85 #87 #104 #105 #106 #107 #117 #121 #130 #133 #134 #162 #164 #165 #167 #169 #172 #173 #181 #183.
PRs cited: #72 #93 #110 #119 #153 #159 #168 #171.
