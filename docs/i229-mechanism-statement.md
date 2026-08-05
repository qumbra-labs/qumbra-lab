# #229 — the mechanism statement (stage 0)

**Paired doc:** [`i229-mechanism-statement-zh.md`](i229-mechanism-statement-zh.md) · EN is authoritative
on technical detail.

Stage 0 of `docs/prompts/i229-fix-builder-prompt.md`. **No fix code is in this branch.** Read against
`main` `37a3fb5`; every code citation is `file:line` at that rev.

---

## 1. The mechanism, in one paragraph

A node that applies a block live and later rewinds past it keeps that block's body in
**`P2pNode::blocks`**, the bounded body-serving cache (`qlab-p2p/src/node.rs:369`, issue #135). That
cache is a **third** ledger of "I have this body", it lives in the P2P layer rather than in the state
machine, and **nothing removes an entry from it when the block leaves the applied chain** — its only
mutation is `insert`, with lowest-height-first eviction (`node.rs:330-350`). When fork choice then
moves onto that block, the state machine needs its body at `fork + 1` and the requester correctly asks
for it (`bask=1@…`). A peer serves it as a whole-body `BlockAnnounce`. And
`on_block_announce`'s **"we already hold this body" early return** (`node.rs:1833-1839`) sees
`self.blocks.contains(&bh)`, clears the in-flight request, sets `body_fetch_progress = true`, and
**returns without calling `ingest_block`** — so `buffer_body` never runs, the body never enters
`pending_bodies`, and `rejoin_main_chain`'s gate reads `Missing` forever. The next requester pass
re-asks, the peer re-serves, the early return fires again. **The loop runs at tick rate until the
cache evicts the entry**, at which point the same arrival takes the ingest path, the rewind happens,
and the held bodies drain ascending in one pass.

**The layer is (c), as ruled — and the interception is one layer above where (c) was being looked
for.** Every citation on this issue so far searched `NodeAdapter` (`buffer_body`,
`is_body_worth_holding`, `pending_bodies`, `rejoin_main_chain`). The body never reaches
`NodeAdapter`. It is discarded in `P2pNode`, before `ingest_block` is called.

## 2. The identification is deductive, not inferred

This thread has twice paid for a plausible story. This one is not a story: the archived numbers
narrow the line by elimination.

`body_reqs` has **exactly three** removal sites (`node.rs`, grep-complete):

| site | line | meaning |
|---|---|---|
| the expiry `retain` | `1018-1019` | entry older than `BODY_REQUEST_TIMEOUT_MS` = 15 s |
| early return, "we already hold this" | `1834` | **no `ingest_block` call** |
| post-ingest, "we now hold this" | `1867` | reached only if the body is now held |

`note_body_ask` (`node.rs:1059`) is called **once per insertion** into `body_reqs`, and `asks` counts
every rung (`node.rs:542-546`). So the ask count divided by the outstanding time is the re-insertion
rate, and the re-insertion rate is bounded by the removal rate.

**The reading of 2026-08-03 09:23:56Z, node0:** `ask h=2984 id=4f2932d634b9 age_s=1200 asks=2195`.

- 2,195 asks over 1,200 s = **1.83 asks/s**.
- The expiry path alone permits **1 ask per 15 s = 0.067/s**.
- **27× the ceiling.** So removals were happening at `1834` or `1867`.
- `1867` requires the body to be held, which would have ended the strand. It did not end. ⇒ **`1834`.**
- `1834`'s condition is `self.blocks.contains(&bh) || self.node.has_stored_body(&bh)`.
  `has_stored_body` is `self.state.chain().block(hash).is_some()` (`adapter.rs:1955-1957`) — the
  **applied store**, the identical predicate `missing_body_hashes` excludes against
  (`adapter.rs:2013`). The hash was *in the ask set* (`bask=1@2983`), so that predicate was **false**.
- ⇒ **`self.blocks.contains(&bh)` was true.** The serving cache is the thing.

No step in that chain is an inference about intent or about unobserved state. It is the ask counter,
the three removal sites, and the fact that two predicates read the same map.

## 3. The five stage-0 questions, in order

### Q1 — code order: where `breq` increments relative to where applying stops

**`breq` is `self.body_reqs.len()` sampled at the END of `tick`** (`node.rs:934`), after
`request_missing_bodies` has run (`node.rs:925`). The ask set comes from `missing_body_hashes`
(`adapter.rs:1993`), whose base is `state_fork_point()` and which returns empty when
`top <= base` — i.e. **when the applied tip is on the main chain**.

**Only one ordering is possible in code: freeze-then-ask.** "Off-main" and "there is something to ask
for" are computed from the *same* comparison — `state_fork_point() < state.tip_height()` — so the ask
set cannot become non-empty before the reclassification. `missing_body_hashes` has no other trigger,
no timer, and no peer input.

🔴 **So the ask is a symptom, and the gated premise resolves in favour of the apply side.** The
30 s same-tick signature does not need to discriminate further: the ordering is settled by
construction, not by the bracket. A stage-1 fix aimed at the requester would be aimed at the symptom.

**And `breq` can never read 0 while stranded, which is why 5/5 instances show `breq ∈ {1,2}` at every
tick.** The entry is removed when the served answer arrives and re-inserted by
`request_missing_bodies` later in the same tick, before the telemetry sample. The oscillation is
invisible; the level is not.

### Q2 — what flips `schain` on a `slag=0` node

`schain=fork` is `applied_tip().is_off_main_chain()`, i.e. `state.tip_hash() !=
chain.main_chain_hash_at(state.tip_height())` — both sides local (`qlab-node/src/telemetry.rs:380-391`).
Two events can move it on a caught-up node, and **the two onsets are one of each**:

- **Arriving headers move fork choice** (`submit_header` → `insert_header`, `adapter.rs:1654`). The
  applied tip is unchanged and is reclassified underneath the node. **This is instance 4 (node3):
  `stipid` identical across the onset tick (`157ed35f7ad2`), `slag=0`, nothing applied.**
- **The node's own rewind + re-apply** lands the applied tip on a branch that is not (or ceases to
  be) main. **This is instance 5 (node2): `stipid` `5a26e60f2e5a` → `fcf3f5fb2e3a` at an unchanged
  height 573.**

**Both are the same mechanism with a different last step, not two entry paths.** The stranding
condition is not "how the tip got reclassified" — it is "**is the body of `main[fork+1]` in my serving
cache and not in my applied store**". A rewind is what usually creates that state (it removes the
block from the applied store, `store.rs:395-411`, while `ServedBodies` is untouched); a fork-choice
move is what makes it *needed*. Instance 4 shows the two can be a minute apart: node3's rewinds at
`23:07:48.777Z` created the state, and the flip at `23:08:48Z` demanded it.

### Q3 — the fork point in `bask`, and where the intention dies

`bask=N@F` is `(missing_body_hashes(MAX_BODIES_IN_FLIGHT).len(), state_fork_point())`
(`adapter.rs:1131-1132`). `F` is the fork point; the single ask is `main[F+1]`, which is **exactly the
one block `rejoin_main_chain` requires in `pending_bodies` before it will rewind**
(`adapter.rs:1429-1433`). So both onsets asking "backward, below their own `stip`" is the requester
working correctly: 556 < 558 and 571 < 573 because the *fork point* is below the applied tip, which is
what being stranded means.

🔴 **The intention dies at `qlab-p2p/src/node.rs:1833-1839`** — the `return` inside
`if self.blocks.contains(&bh) || self.node.has_stored_body(&bh)`. That is the missing gate, named to
file:line. Everything downstream of it is correct and starved: `buffer_body` is never called,
`is_body_worth_holding` is never evaluated, `pending_bodies` never receives the body,
`rejoin_gate_observed` honestly reports `Missing` (`adapter.rs:1054-1069`), and `drain_pending_bodies`
has nothing to drain at that height.

### Q4 — the `stipid` swap at an unchanged height

`rewind_to` (`qlab-node/src/node.rs:877-932`) rebuilds the applied chain from the retained ancestor
path only; the undone suffix leaves the applied store and enters the `retained` possession archive
(#198). A rewind to height *h* followed by application of buffered bodies up the *other* branch
therefore produces a **different identity at the same height** — node2's `5a26e60f2e5a` →
`fcf3f5fb2e3a` at 573, after `REWIND … → 16093980 @ 571`. node3 skips it because at its onset tick it
had not re-applied anything: its rewinds had already happened a minute earlier and the flip was
caused by arriving headers.

**So the swap is a consequence of which branch had a buffered body available at the moment of the
rewind, not a second mechanism.** It has no bearing on whether the node strands.

🔴 **And it corrects an observation-level puzzle.** The two `REWIND` lines at `23:07:48.777146Z` and
`23:07:48.777194Z` (48 µs apart, different from-tips at the same height 557) are **not two
simultaneous rewinds.** `REWIND` is drained from a journal and printed in a batch on the message-pump
cadence (`qumbra-node/src/run.rs:1585-1597`, `adapter.rs:1437-1440`), so two lines microseconds apart
are two events that occurred anywhere inside the preceding pump interval, printed together. The node
held one applied tip at a time; between the two rewinds it applied buffered bodies up to a second,
different 557. **Nothing holds two applied tips.**

### Q5 — why #130 (a)'s ascending catch-up does not fire

#130 (a) / PR #142 applies bodies **it holds**: `drain_pending_bodies` walks `pending_bodies`
ascending (`adapter.rs:1460-1494`). It is in `NodeAdapter`. The body is discarded in `P2pNode`, one
layer above, before `ingest_block` is ever called. **#130 (a) is not defeated — it is starved.** Its
guarantee is conditional on arrival ("a body whose header is in this node's chain is applied as soon
as the state tip reaches its parent", `adapter.rs:2120-2122`), and this defect breaks the antecedent.

The same is true of #178's `rejoin_main_chain`, #162's retention rule, and #182's requester: every
piece of machinery this issue has cited is correct. **Exactly one seam is wrong, and it is the one
nobody had cited.**

## 4. What starts it, what sustains it, what ends it

### Starts

Two facts must hold at once, and both are ordinary:

1. The node **accepted a block live** — a whole-body `BlockAnnounce` with a header new to it, so
   `complete_block` cached the body (`node.rs:1972-1980`; caching is gated on `Accepted`, and
   `Accepted` ⟺ `insert_header` was `Ok`, `adapter.rs:1654-1671`). Its own mined blocks enter the
   same cache (`node.rs:847`).
2. That block **left the applied store** (a rewind) and **fork choice later selected it** (or its
   branch), so the state machine needs its body again.

Both are routine branch churn — every host in both onset windows rewinds 1–2 blocks repeatedly. **The
discriminator between a host that recovers and a host that strands is only whether the body it now
needs is sitting in its own serving cache.** node1 crossed the identical 573 fight in the same minutes
and did not strand because its second rewind (`5a26e60f @ 573 → 14146440 @ 572`) left its applied tip
**on** the main chain — `state_fork_point() == tip`, empty ask set, nothing to be starved of.

### Sustains

The loop, plus four consequences that are all observed:

- **`gate=missing` is permanent** while the entry is cached. `bdrop=0` throughout, because nothing is
  dropped — see §6 for why that field could never have seen this.
- **`pend=52`**: bodies at heights *above* the strand keep arriving, are accepted, and accumulate in
  `pending_bodies`, where none of them is applicable.
- 🔴 **`uex` can never arm — and this answers #222.** The early return sets
  `body_fetch_progress = true` (`node.rs:1836`), consumed once per tick (`node.rs:931-934`), which
  resets `unserved_since_ms` to `None` in `observe_body_fetch` (`adapter.rs:961-972`). On a stranded
  node that fires **every tick**, so #201's exemption cannot accumulate a window. #222's leading
  hypothesis was "`body_fetch_progress` resets the counter whenever *any* body arrives"; the sharper
  truth is that **the resetting body is the very body that never applies**. `uex=0` on every stranded
  sample across all five instances.
- **The node stops mining and abstains from its slot.** The lag gate refuses
  (`adapter.rs:1714-1736`), which removes its hashrate and its keys — the quorum-margin cost #223
  named, and the variant split #226 named. Neither is caused by this defect's *fix*; both are
  downstream of the strand.

### Ends

🔴 **Eviction from `ServedBodies`, and it is not an accident.** `ServedBodies` has no removal API — the
only mutation is `insert`, which evicts **lowest `(height, hash)` first** until back inside
`MAX_SERVED_BODIES = 128` (`node.rs:107`, `node.rs:341-349`). `MAX_SERVED_BODY_BYTES = 8 MiB` is
unreachable on a coinbase-only T0 (per-entry weight is `txs_weight + 40` B). So the trapped entry
leaves when roughly 128 insertions have pushed the cache's low end past it. On the tick that happens,
the next served copy takes the ingest path: `buffer_body` → `drain_pending_bodies` →
`rejoin_main_chain` rewinds → the accumulated bodies drain ascending in one pass, **and the same
`on_block_announce` call clears `body_reqs` at line 1867.**

**That is why `breq → 0` and the `stip` unfreeze are coincident 5/5, two of them bracketed to 61 s:
they are not two correlated events, they are one function call.** And it is why the catch-up is a
single step (88 blocks in the 08-03 instance, `slag 77 → 17` in ~16 min in instance 4) rather than
gradual — `pending_bodies` was already full of the blocks above the strand.

**Quantitative prediction, stated as a prediction.** Duration ≈ 128 / (accepted bodies per height)
blocks × block time, so `slag` at unfreeze ≈ 128 / (bodies per height). Measured `slag` at unfreeze:
**76, 84, ~70, 77, 74** across the five instances ⇒ 1.5–1.8 accepted bodies per height, which is
exactly the sibling rate the 1–2-block rewind churn implies. Durations 1 h 25 m – 2 h 09 m at the
measured 86 s mean interval agree. **This is consistent, not verified** — see §7 for the one test that
would verify it.

> ### 🔴 CORRECTION 2026-08-05, from the stage-1 measurement — the arithmetic above does not hold
>
> The eviction experiment was built and run against the pre-fix condition. **The qualitative claim
> survives and is now measured: the strand ends by cache eviction.** The cache fills to exactly
> `MAX_SERVED_BODIES = 128` entries and the applied tip moves only once the trapped entry is
> displaced. That is the "self-heal was never a heal" finding, and it is confirmed.
>
> **The relation `slag at unfreeze ≈ 128 / (bodies per height)` is retracted.** In a two-node sim
> producing exactly one body per height, the strand should then have ended at announcement 128. It
> did not:
>
> | delivery time per announced block | announcements to unfreeze | cache at unfreeze |
> |---|---|---|
> | 30 ticks | **142** | 128 (full) |
> | 6 ticks | **325** | 128 (full) |
>
> The count is bounded below by the cap and **inflated by delivery loss**, converging toward 128 only
> as delivery stops being the binding constraint. So the cap sets a floor on the duration, not the
> duration — and the production coefficient of 1.5–1.8 bodies per height, which I derived *backwards*
> from `slag` 74–84, is **not established by anything measured here.** It remains one arithmetic
> consistent with the observation, and I should not have written it as the explanation.
>
> **The sub-finding that produced the gap is worth more than the retracted law.** The refusal loop's
> own traffic is what starves delivery: V re-asks and the peer re-serves at tick rate, throttled
> frames are dropped and deliberately not scored (#91, ahead of decode), so **the loop delays the
> eviction that ends it — and a busier net strands for longer.** That is the opposite of what "the
> accident arrives reliably" predicts, and it means the ~2 h constant is not a constant at all: it is
> a floor of `MAX_SERVED_BODIES` blocks plus however much the node's own thrashing costs it.
>
> **Consequence for the ROADMAP correction** (design-side, coordinator's): the line may say the
> self-heal is a cache-eviction deadline rather than recovery. It may **not** say the duration is
> `128 / (bodies per height)` blocks.

🔴 **This retires "the expected wait for an accident."** The constant is a cache-capacity deadline, and
the ROADMAP line that survived the 2026-08-03 correction as *"waiting is defensible because the
accident arrives reliably"* now has a mechanism instead: the wait is `MAX_SERVED_BODIES` blocks. It is
reliable because it is a counter, which is a stronger statement than the one it replaces — and a
worse one operationally, because it scales with nothing an operator can influence.

## 5. Where this leaves the record — three corrections

1. 🔴 **`bdrop=0` never had the reach it was read as having.** `bdrop` is
   `metrics.observe_body_refusal(...)` from the **apply-failure arm of `drain_pending_bodies`**
   (`adapter.rs:1491`) and nothing else. `buffer_body`'s admission refusal (`adapter.rs:1371`) has
   **no counter at all**. So "bdrop=0, therefore `is_body_worth_holding` is not refusing it" was
   true here for a stronger reason than the one given — `is_body_worth_holding` is never *reached* —
   but the general inference does not hold, and a future strand entered through the admission gate
   would read `bdrop=0` too. **Recorded as an instrumentation gap, not fixed in this branch.**
2. **#198 reasoned about exactly this deadlock and stopped one ledger short.**
   `qlab-p2p/src/n1.rs:228-233` names the four callers of "applied" and says of the fourth:
   *"`on_block_announce`'s 'we already hold this body' early return … would, if widened, have a node
   that rewound past a block discard the re-announced body as redundant. That is the same deadlock one
   seam over, so the two predicates stay apart by construction."* The reasoning is right and the
   conclusion held for `has_stored_body`. **`self.blocks` is a third ledger in the same `if`, and it
   was not in that analysis** — it already answers "we hold this body" across a rewind, for free.
3. **The two-`REWIND`-in-one-millisecond puzzle is a printing artefact**, not a state-machine
   anomaly — §3, Q4.

## 6. Unknowns, named

- **The eviction arithmetic is consistent, not measured.** Nothing counts cache insertions or
  evictions, so "128 insertions" is inferred from `slag` at unfreeze across five instances rather
  than observed. A cache-eviction counter would settle it; there is none.
- **Which of the two entry paths dominates** is unknown and does not matter for the fix. Instance 4
  arrived by fork-choice move, instance 5 by rewind-and-reapply; three earlier instances have no
  onset coverage at all.
- **Whether a node can enter the same trap without a rewind** — via a body accepted-and-buffered,
  then dropped from `pending_bodies` by the retention rule while staying in the serving cache — is
  reachable in code (`adapter.rs:1512-1520`) and would be indistinguishable on the telemetry line
  except that it *would* raise `bdrop`. `bdrop=0` rules it out for these five instances and not in
  general.
- **The 07:08:48 / 07:09:38 50-second ordering** (instance 4's onset preceding finality's last
  advance) is consistent with the strand removing node3's 5 keys from the variant it had been voting
  on, but the corrected round table shows every slot closing, so **nothing in this mechanism explains
  or needs it.** It stays #226 / #223 territory.
- **Tick period.** 1.83 asks/s implies a ~550 ms tick on the stranded host. That is unremarkable but
  it is not measured, and it is not load-bearing: the 27×-the-ceiling argument holds at any tick
  period faster than 15 s.

## 7. What stage 1 inherits (guardrails, not a design)

Written to be bounced or ratified, not to pre-empt the fix.

- **The seam is `qlab-p2p/src/node.rs:1833-1839`.** It is P2P-layer, node-side, and touches no
  message type, no payload and no consensus rule — **no wire or genesis change**, so it rolls without
  a re-mint. If a candidate fix needs either, that is the STOP the task book names.
- **The reproduction that verifies §4 before anything is changed**, and it needs no host: two
  in-process nodes, a branch fight at one height, accept both siblings live (so both bodies enter
  `ServedBodies`), rewind past the one that wins, and assert that the served body never reaches
  `pending_bodies` while the cache holds it — then evict and assert recovery. **If that test does not
  go red on `main`, this statement is wrong** and stage 1 should not proceed.
- **The healthy-recovery baseline to preserve**: `breq → 0` ⟺ `stip` unfreeze, coincident, 5/5. Under
  §4 that coincidence is structural (one call site), so a fix that keeps the ingest path intact keeps
  it; a fix that clears `body_reqs` somewhere new would break it silently.
- **The negative acceptance criterion**: the six healthy rewinds in fifteen minutes must stay healthy.
  Any fix must not turn "I hold this body in cache" into a rewind trigger — the arrival-driven
  property the reviewer argued for is not challenged by this mechanism and should survive it.
- **The observable, still owed and still first in value** (item 4 of the ruling): `BODYWAIT` already
  says `gate=missing` and `mine=refused-lag`. What it cannot say is that **this node believes it
  already has the body it is asking for** — the one sentence that would have made this a five-minute
  diagnosis.
- **`adapter.rs:1341-1343`'s comment** still justifies the body-buffer bound with a claim about
  rewind depth that `rewind_path` does not enforce (the coordinator's own correction, 2026-08-03).
  Unchanged here; stage 1 owns it.

## 8. What I did not run

**At the time this statement was submitted for ratification, nothing in the branch was code**, so the
workspace suite was not run and was not the bar for stage 0: no test was added, no crate touched, and
`git diff --stat` against `main` was docs only. The rig lock was not taken and no heavy job was
started.

**Stage 1 was ratified on 2026-08-05 and its runs are recorded on PR #264**, including the
reproduction going red on `main` in both directions and the eviction measurement that produced the
correction in §4.

**Evidence read:** issue #229 in full (body + 23 comments), `qumbra-ops/i229-onset-windows-20260805/`
(all 8 four-host logs), and `main` `37a3fb5` at every line cited. Nothing was run against a host and
no host was touched.
