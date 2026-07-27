# M11 halt-height upgrade — mechanism + drill run doc

> **Scope label: LOCALHOST/DOCKER.** The drill runs on the 4-node docker-compose
> rehearsal net on one dev rig. **NO WAN-latency claims.** What this run
> establishes is that the halt-height upgrade *mechanism* behaves as
> `committee-and-governance.md` §4 specifies — the committee stops checkpointing at
> exactly the announced height, ≥⅔ restarts on the new binary, finality resumes on
> the new rules, an old-binary miner's branch grows and never finalizes, and a
> scheduled upgrade can be stood down before the height. It is **not** evidence
> about upgrade behaviour under WAN latency or at production committee scale.

**Issue:** [#74](https://github.com/lai3d/qumbra-lab/issues/74).
**Governing spec:** `qumbra-design/committee-and-governance.md` §4 (EN authoritative;
`committee-and-governance-zh.md` §4). Decisions H1–H5 + N1–N2 ratified by the
coordinator on the issue, 2026-07-26.

## Rig + provenance (bench discipline §2)

| Field | Value |
|---|---|
| Repo rev | `claude/halt-height` (base main `5a24e49`); final SHA stamped at PR |
| Host | Apple M5 Max, 36 GiB |
| OS | macOS (Darwin 25.5.0) |
| Container runtime | Docker Desktop, aarch64 Linux VM |
| RandomX | `randomx-rs` 1.4.1 (light mode) |
| Block time | 75 s (FROZEN, consensus-parameters §2) · Mining clock `WallClock` |
| Power state | AC power |
| Genesis | `4a75b3b8…c2c3` — **unchanged**; this baton moves no FROZEN v1.0 value (H5) |

## What this baton built

| Piece | Where | Decision |
|---|---|---|
| `HaltPlan` (None / Armed / Cancelled), cadence-grid rule, `Halting`/`Halted` regime, post-halt rule domain | `qlab-devnet::halt` | H1, H2, N1 |
| `FinalityStatus::{Halting, Halted}` + telemetry wire 2/3 | `qlab-devnet::ebbflow`, `qlab-node::telemetry` | H2 |
| Frozen-parameter digest + `Revision` | `qumbra-node::revision` | H4 |
| `RELEASE` constants, resume gate, `HaltMarker` | `qumbra-node::release` | H1, H4, N1 |
| Halt enforcement (mine / accept / **sign** / finalize) | `qlab-p2p::adapter` | H2 |
| Startup gates, marker maintenance, `halt-status` CLI | `qumbra-node::run`, `main.rs` | H1, H4 |
| Five release binaries + the four drills | `deploy/docker/*`, `soak.sh` | scope 6–7 |

### The halt height is a release constant, reachable from nothing else (H1)

`RELEASE` is a `const` in `crates/qumbra-node/src/release.rs`, selected at compile
time by cargo feature. There is no config key, no CLI flag, and no environment
variable that can change where a node pauses. `NodeConfig` additionally gained
`serde(deny_unknown_fields)`, so a config file containing `halt_height = 999` is a
hard parse error rather than a silent no-op — "you cannot do that" instead of "that
did nothing".

The drill therefore builds **purpose-built binaries**, which is what a real upgrade
is anyway: an operator swaps an executable.

### The halt boundary is a finalized boundary (H2)

H must be a multiple of `CHECKPOINT_CADENCE_BLOCKS` (8); a binary whose halt height
is off the grid refuses to start with a clear error (not a panic). The three acts,
in order of load:

1. **The committee stops signing checkpoints above H.** Gated in
   `make_checkpoint_guarded`, as close to the signature as it can be, so a halted
   member produces no vote rather than one that is filtered later. The checkpoint
   **at** H is still produced — it is what makes the boundary final.
2. Upgraded nodes stop mining above H and reject blocks above H. A peer offering
   post-H blocks is **not penalised**: it is on a different release, not
   misbehaving.
3. A halted node also refuses to *finalize* above H — it must not finalize a chain
   it will not accept.

The process stays alive; RPC and telemetry keep serving. `regime=Halting` from
reaching H until H's checkpoint finalizes, then `regime=Halted`. A net that cannot
close finality at H stays visibly in `Halting`, which is the honest outcome and the
signal **not** to swap binaries yet.

### The revision digest — exactly what it covers, and why

The digest is `keccak256` over a canonical, name-prefixed encoding of the FROZEN
v1.0 constant table (`FrozenParams`), pinned at

```
19564ecaffd8f78e69b31840cf465b3b34553968813f7fcaff83194077534571
```

**Covered — all 38 frozen fields:**

| § | Fields |
|---|---|
| 1 proof/consensus | `consensus_fri`, `log_height`, `consensus_wire_bytes`, `agg_leaf_lane`, `agg_interior_lane`, `consensus_hash`, `tree_depth` |
| 2 emission | `block_time_secs`, `bessel_per_qmb`, `r0_qmb`, `decay_d`, `tail_qmb`, `coinbase_maturity_blocks`, `hard_cap` |
| 3 reward split | `split_miner_pct`, `split_committee_pct`, `split_treasury_pct` |
| 4 committee/staking | `committee_size`, `quorum`, `epoch_length_blocks`, `self_bond_qmb_steady`, `bond_ramp_qmb`, `equivocation_slash_pct`, `downtime_jail_threshold_pct`, `downtime_jail_window` |
| 5 fees | `fee_2x2_bessel`, `fee_4x4_bessel`, `fee_8x8_bessel` |
| 6 block weight | `weight_free_zone_bytes`, `weight_hard_cap_multiple`, `weight_long_window`, `weight_lt_cap_num`, `weight_lt_cap_den`, `weight_st_cap` |
| 7 anchors | `anchor_max_age_blocks`, `anchor_bucket_blocks`, `anchor_retained_roots` |
| 8 denomination | `ticker` |

**Excluded, deliberately:**

- **`checkpoint_cadence_blocks_not_frozen`** — the one field of `FrozenParams` that
  is explicitly *not* frozen (protocol-spec §7 flags the cadence `[full-M8]`).
  Covering it would make the digest claim frozenness the value does not have, and
  would demand a revision document for a legitimately tunable knob. That is how
  digest discipline dies: an operator who must bump the revision for routine
  changes learns that bumping the revision means nothing. The cadence is not
  unguarded — the halt height is bound to it at every startup by the grid rule.
- **committee₀'s 21 verifying keys, the genesis block, the genesis difficulty, the
  network label** — already pinned by the genesis hash, which every node asserts on
  startup. Two pins on the same bytes is redundancy, not assurance.
- **Every `params_devnet` knob annotated testnet-tunable** — LWMA window/clamps,
  key-epoch schedule, degraded-mode lag, jail blocks, the tally caps.
- **Code.** The digest covers the frozen constant *table*, not the logic that
  consumes it. A binary that keeps every frozen value and changes how it applies
  them produces an identical digest. Stated plainly because it is the real limit:
  this makes an undocumented **parameter** change impossible-by-construction; it
  does not and cannot make an undocumented **rule** change impossible. The guard
  against undocumented rule changes is the halt itself — a rule change must ship as
  an upgrade with its own halt height.

  **🔴 That exclusion is a constraint to defend, not a gap to close.** The same
  property does two jobs: it is a scoping limit (the digest cannot catch an
  undocumented rule change) *and* the enabling property that makes the gate usable
  (a release changing only code digests identically, so it starts with no
  ceremony). Extending the digest over the consuming logic would read as a
  strengthening; what it would actually do is make every release produce a
  different digest, so every release would demand a declared transition, and the
  declaration would stop meaning "the parameter set moved" and start meaning "a
  release happened". That is the same death this doc already refuses on the other
  side — the cadence is excluded because demanding a revision document for a
  tunable knob teaches operators the ceremony is empty. Widening kills it from the
  opposite direction. The burden on anyone adding to the digest is therefore not
  "does this close a gap" but "does this value move **only** when the frozen
  parameter set moves". Written into `crates/qumbra-node/src/revision.rs` at the
  function a widener would edit, since that is where they will be standing.

**Coverage cannot drift silently.** The digest preimage destructures
`FrozenParams` with no `..` rest pattern, so adding a field to the frozen table
fails to compile until an author decides, explicitly, whether it belongs in the
digest. Tests assert that each of the 38 covered fields moves the digest, that the
excluded field does not, and that swapping two equal-width fields moves it.

### The resume gate, and why it is anchored on an on-disk marker (H4)

A node that reaches H writes `halt.marker` into its data dir: the height, the
revision that halted it, that revision's frozen digest, and whether the boundary
finalized. Any later binary that would carry the node **past** the marked height
must both carry a revision and *declare* `resumes_from == that height`, or it
refuses to start.

The marker is what makes this non-dodgeable. If the gate depended only on the
resuming binary declaring its own intent, a binary that simply declared nothing
would sail through. Because the halted binary already wrote the fact down, silence
is refused too. A **corrupt** marker is an error, never read as "never halted" — a
node that halted must not become resumable by mangling its own evidence.

Two consequences worth stating, because they surprised us:

- Handing a halted node the *pre-announcement* v1.0 binary is refused
  (`UndeclaredResume`). That is correct: "fixing" a halted node by downgrading to a
  binary that does not know about the halt is precisely the mistake the marker
  exists to catch. It is also why the drill's old-binary miner is a node that
  **never armed** — see the drill topology below.
- Restarting the *same* halted binary is not a resume, and is allowed. An operator
  must be able to stop and inspect a halted node.

### Cancellation is a release, not a switch (N1)

Standing an upgrade down before H is a new release carrying
`HaltPlan::Cancelled { height, reason }` — the same *kind* of object as arming it,
for exactly H1's reason. It keeps the cancelled height rather than reverting to
`None`, on three grounds:

1. **Auditability.** `CANCELLED — the upgrade at height 16 was stood down (reason)`
   on the startup banner is something an operator can diff against the
   announcement. A silent revert to "no halt scheduled" is indistinguishable from
   the pre-announcement release, so an operator could not tell whether they
   deployed the stand-down or forgot to deploy the arming.
2. **Typos are still caught.** A cancelled height is grid-validated exactly like an
   armed one. A stand-down naming an impossible height means somebody cancelled a
   different upgrade than the one that is armed.
3. **It composes with the marker.** On a node that already halted at H, a
   cancellation for H is obviously the wrong binary, and the resume gate says so
   instead of silently resuming.

### The post-halt rule domain — a property of the mechanism (ratified 2026-07-26)

The drill upgrades from revision `v1.0` to `v1.0.1-drill`. It moves **no** FROZEN
v1.0 value — the two revisions' frozen digests are byte-identical — and changes
only the revision identifier (H5).

For that to be an *upgrade* rather than a no-op, the identifier has to be visible
to consensus above the boundary. §4's honesty note ("old-binary miners can keep
producing blocks past the halt-height, but those blocks can never finalize") only
holds if the upgraded population can *tell* a pre-halt block from a post-halt one.
If the post-halt rules were byte-identical to the pre-halt rules, an old miner's
branch above H would be perfectly valid to the upgraded net, heaviest-chain would
arbitrate, and the upgraded committee could *legitimately* finalize it — the
opposite of what §4 promises, and drill (a) would pass while proving nothing.

**Coordinator ratification (2026-07-26): adopted, and deliberately not confined to
the drill.** Without domain separation, "those blocks can never finalize" is a
statement about what the committee chooses to do; with it, it is a statement about
what the protocol permits. A drill that proved a property the real upgrade path
does not have would be its own kind of dishonesty, so the rule domain is a property
of **every** resuming release, not a drill prop. `Release::rule_schedule` makes it
unconstructible to resume past a boundary without one — the only release that could
is one carrying no revision, which H4 refuses outright
(`resuming_always_carries_a_post_halt_rule_domain`).

The mechanism: for heights **> H** the value compared to the difficulty target is
`keccak256(tag ‖ revision-digest ‖ engine-hash)` instead of the raw engine hash.
Work cost is unchanged (one extra Keccak per nonce trial), the difficulty target is
untouched — it changes *which* hashes count, not how many are needed. At and below
the boundary it is byte-identical to the v1.0 rules, so no pre-halt block ever
changes meaning.

**H5 is not violated.** The revision moves no FROZEN v1.0 value; the PoW
instantiation is a `[full-M8]` open item in protocol-spec, not a frozen constant.
The precedent is §4's own Monero citation — Monero changes the PoW *algorithm* at
each scheduled fork; domain separation is the mildest form of the same move.

> **Design note, recorded rather than erased:** the first implementation
> domain-separated the RandomX *key seed*, and the in-process drill caught that it
> was wrong. `KeccakPow` documents that it ignores the seed, so a seed-level domain
> would have been a real rule change under RandomX and a silent no-op under Keccak.
> A consensus rule whose force depends on which PoW engine is compiled in is not a
> consensus rule. The fix wraps the engine's *output* —
> `pow_value(pow.pow_hash(header, seed), …)` — which makes engine-independence
> **structural** rather than something each engine must be checked for: "KeccakPow
> ignores the seed" stops being a fact needing compensation and becomes an
> irrelevant one. No engine behind the `PowEngine` trait, present or future, can
> opt out.

`Revision::digest` binds the identifier *and* the frozen digest, so two inert
revisions (same frozen set, different name) are still distinct rule sets. Without
that, a second no-op upgrade would have no boundary at all.

### 🔴 Which layer refuses an old-binary block — and why the distinction matters

This changed what drill (a) proves, and the run doc has to be precise about it
because §4's update will be written from these logs.

| Phase | Layer | What happens | Evidence |
|---|---|---|---|
| **While halted** (tip = H, before the swap) | **Release** | The node has stopped. The block is *not judged invalid* — it is `Ignored("above halt height")`, not relayed, not synced toward, and **the sender is not penalized**. | telemetry `hignore=` climbs, `powrej=` flat |
| **After the swap** (post-halt rules in force) | **Header validation** | The block's PoW value does not meet the target under the post-halt domain: `ValidationError::PowUnsatisfied` → `Rejected("invalid header: pow")`. It never enters `ChainState` at all. | telemetry `powrej=` climbs, `hignore=` flat |

The two counters are on every telemetry line (`hignore=` / `powrej=`), so the
docker drill answers "which layer?" from the logs rather than from a narrative.

**Reading the counters across a swap.** They are per-process and reset when a
container is recreated — which a binary swap necessarily does. That is what makes
the post-swap signature meaningful rather than an artefact to explain away: a
resumed release carries no halt, so `hignore` *should* stay at 0 for the life of
that process, while `powrej` climbs. `soak.sh` records the pre-swap values to disk
at `halt-arm` and prints the before/after pair in drill (a), so the comparison is
against a recorded number rather than a remembered one. Raw evidence is appended to
`docs/m11-halt-height-evidence.log`.

#### Observed: `final=-` immediately after a swap, then `final=16`

Not a caveat — a recorded sighting, from the pre-drill resume smoke on the real
binary (`docs/m11-halt-height-evidence.log`):

```
TELEMETRY tip=16 final=-  stall=16 age_s=-    diff=77 … regime=Degraded halt=- hignore=0 powrej=0
TELEMETRY tip=17 final=16 stall=1  age_s=4995 diff=77 … regime=Final    halt=- hignore=0 powrej=0
```

The freshly-swapped node reported **no finalized head at all** for its first three
telemetry samples, then reported 16. The finality *tracker* is deliberately not
persisted (M10-T0-5 / S7 — it rebuilds from re-gossip); the chain's finalized head
was intact on disk the whole time and nothing was un-finalized.

It is written up as an observation because an operator who has read the prose is
still going to feel it during an upgrade, at the moment they are least able to
afford a wrong reading. One recorded sighting of the exact lines is worth more than
a paragraph of reassurance.

The mechanical consequence: drill (b)'s assertion is one-sided and numeric —
"finality never advances **above H** below quorum" — not "`final` is unchanged",
which would have fired a false stop-point on every single run.

**Note for §4.** §4 currently describes the second kind of outcome — blocks that
are *accepted but can never finalize*, with the committee as the thing that keeps
the upgrade clean. What the domain separation produces post-swap is **stronger**:
the old branch is not merely unfinalizable, it is *invalid* on the upgraded net and
never reaches fork choice. Before the swap, during the halt window, the old branch
is neither — it is simply not acted on, and the peer is not blamed. Whether and how
to reflect that in §4 is the coordinator's call and the coordinator's wording; this
doc reports the observation, not the amendment.

## Drill topology

N=4, committee 21 keys split **6/5/5/5** (node0=00..05, node1=06..10, node2=11..15,
node3=16..20), quorum 15. Halt height **H = 16** — on the cadence grid (2 × 8) and
deliberately low so each drill is minutes at the frozen 75 s block time.

| Node | Keys | Binary in the (a)/(b)/(c) sequence |
|---|---|---|
| node0 | 6 | `qumbra-node-armed` → `qumbra-node-resume` |
| node1 | 5 | `qumbra-node-armed` → `qumbra-node-resume` |
| node2 | 5 | `qumbra-node-armed` → `qumbra-node-resume` (via `-norev`, which must refuse) |
| node3 | 5 | `qumbra-node` (plain v1.0) throughout — **the §4 old-binary miner** |

node3 runs the plain binary *from genesis*, never the armed one. That is what an
old-binary miner actually is under §4 — someone who never deployed the
halt-carrying release — and it is also forced by the resume gate: a node that *has*
halted cannot be handed the old binary (see above).

Key arithmetic, which is the whole of drills (a) and (b):

- node0 + node1 upgraded = **11 keys < 15** → finality must not resume. Drill (b).
- node0 + node1 + node2 upgraded = **16 keys ≥ 15** → finality resumes, *without*
  node3's 5 keys. §4's "≥⅔ restarts on the new binary" — the committee is what
  makes the upgrade clean, not miner unanimity.

## Drill results

> **STATUS: the docker drills have not been run yet** — the rig is held by the
> 4-node cross-epoch soak and by the queued heavy-prover baton (#24). This section
> is filled in from the live run; the in-process results below are already on
> record and are what the docker run is expected to reproduce at wall-clock scale.

### Deterministic in-process drills (no docker) — ✅ PASS

These run in the ordinary test suite and are the reason the docker drill is
expected to be a confirmation rather than a discovery.

| Drill | Test | Result |
|---|---|---|
| (a) H3 hybrid honesty | `qlab_p2p::adapter::drill_a_old_miner_grows_past_h_and_never_finalizes` | ✅ |
| (b) N2 ⅔ gate | `qlab_p2p::adapter::drill_b_finality_does_not_resume_below_quorum` | ✅ |
| (c) H4 no revision | `qumbra_node::release::drill_c_resume_without_a_revision_refuses_to_start`, `qumbra_node::run::drill_c_no_revision_refuses_to_resume_a_halted_data_dir` | ✅ |
| (d) N1 stand-down | `qumbra_node::release::drill_d_a_cancelled_release_does_not_halt`, `qlab_p2p::adapter::drill_d_a_cancelled_upgrade_does_not_halt`, `qumbra_node::run::drill_d_cancelled_release_mines_through_the_cancelled_height` | ✅ |
| Halt semantics (H2) | `qlab_p2p::adapter::halt_stops_mining_accepting_and_signing_above_h`, `…halt_committee_refuses_to_sign_or_finalize_above_h` | ✅ |
| Domain separation is a mechanism property | `qumbra_node::release::resuming_always_carries_a_post_halt_rule_domain` | ✅ |
| Resume path on the REAL binary (both halves) | pre-drill smoke, `docs/m11-halt-height-evidence.log` | ✅ raw evidence, no conclusions drawn |
| An old-release peer is not penalized | `qlab_p2p::n1::only_rejected_is_a_peer_fault` | ✅ |
| Resume path (scope 5) | `qumbra_node::run::the_upgraded_release_resumes_at_h_without_a_resync` | ✅ |

Drill (a) in process asserts all four halves of §4's claim: the old branch
**grows**; it **never finalizes** however long it grows; the fork is **bilateral**
(neither side can silently absorb the other, so only finality arbitrates); and the
invariant holds — **no reorg past a finalized checkpoint**, with both sides still
agreeing on the finalized boundary block.

It also asserts the **layer attribution** directly. While halted, the five
old-binary blocks are `Ignored("above halt height")` with `halt_ignored = 5,
pow_rejected = 0` — the release layer, no fault attributed to the sender. After the
swap, the first old-rule block is `Rejected("invalid header: pow")` with
`halt_ignored` unchanged and `pow_rejected = 1`, and the test asserts the failing
check is exactly `ValidationError::PowUnsatisfied` by calling
`validate_header_under` directly — so the claim is about the post-halt domain and
not about a coincidental difficulty or timestamp mismatch. The bilateral half is
asserted at the same precision: the old binary rejects the upgraded net's block
with the same error, at the same layer.

### 0. Genesis rehearsal — ⏳ PENDING

### 1. `halt-arm` — the halt itself — ⏳ PENDING

### 2. Drill (b), the ⅔ gate — ⏳ PENDING

### 3. Drill (a), the hybrid honesty case — ⏳ PENDING

### 4. Drill (c), resume without a revision digest — ⏳ PENDING

### 5. Drill (d), the stand-down — ⏳ PENDING

## Acceptance suite

**⏳ PENDING — the acceptance bar is a single unfiltered
`cargo test --release --workspace` run, and it has not been run.** The rig is held
by the cross-epoch soak until ~22:00; this baton is first in the release queue.
Baseline 569 as of 2026-07-26 (re-check: #24 may land first).

What *has* been run, explicitly **not** acceptance (bench discipline §5: a filtered
run structurally cannot see other modules' cross-checks):

| Scope | Result |
|---|---|
| `cargo check --workspace --all-targets` | clean, 0 errors |
| `cargo test --release -p qlab-devnet -p qlab-p2p -p qlab-node -p qumbra-node` | **all green** — qlab-devnet 134, qlab-p2p 93, qlab-node 39 (+13 across its other targets), qumbra-node 62 (incl. the `verifier::` real-STARK cases and the RandomX composition) |

The four crates above are the ones this baton touches. The workspace suite is still
owed because the parts it does *not* touch — `qlab-bench`'s m4 lanes above all —
are exactly where a cross-module drift would surface.

## STOP-POINT watch

The four stop-points from the task-book, and what the tooling does about each:

| Stop-point | Watch |
|---|---|
| **Two conflicting checkpoints finalized at any height, or any reorg past a finalized checkpoint** | `soak.sh halt-drill-a` stops everything and instructs the operator to preserve state if the un-upgraded branch ever finalizes above H, or if an upgraded node's finalized head falls below the boundary. This is the invariant the whole mechanism exists to protect. |
| Building the mechanism requires changing a FROZEN v1.0 value | Not triggered. The genesis hash is unchanged at `4a75b3b8…c2c3` and the frozen digest is asserted identical across both drill revisions. |
| The resume path requires a re-sync from genesis | Not triggered. `the_upgraded_release_resumes_at_h_without_a_resync` asserts the upgraded binary opens the same data dir at tip H with block H byte-identical — no re-sync, no re-mining. |
| Anything contradicts `committee-and-governance.md` §4 | Not triggered; see the honest remainder for the one judgement call flagged for ratification. |

## Honest remainder

1. **The docker drills have not been run.** Everything above the "Drill results"
   section is mechanism + deterministic in-process evidence. The wall-clock,
   multi-process, real-RandomX confirmation is owed.
2. ~~The post-halt rule change is a design call awaiting ratification.~~
   **RATIFIED 2026-07-26**, and widened: it is a property of the mechanism, not of
   the drill. See "The post-halt rule domain" above.
3. **The digest cannot see code.** Stated above and worth repeating: undocumented
   *parameter* changes are now impossible by construction; undocumented *rule*
   changes are not, and never can be by this route.
4. **`validate_body` still does not bind `header.tx_body_commitment` to
   `body.commitment()`.** Found while looking for a rule-change surface; it is
   pre-existing (not introduced here) and out of this baton's scope, but it means a
   block body is not cryptographically bound to its header on the ingest path.
   Recorded for a follow-up issue.
5. **Peer-scoring defect found and fixed during this pass, not in the original
   submission.** The adapter's comment claimed an old-release peer offering post-H
   blocks was not penalized, but the p2p layer penalized every `Rejected` outcome
   uniformly, so a halted node would in fact have banned honest peers still mining
   — partitioning the net during the upgrade window. Fixed by adding
   `IngestOutcome::Ignored` (well-formed, not acted on, sender not at fault) and
   routing every penalty decision through one `is_peer_fault` predicate. The
   coordinator's diff read credited the property to the comment; the behaviour did
   not match it until now.
6. **H = 16 is a drill value.** Production halt heights are chosen per upgrade and
   announced in advance; nothing here proposes 16 as policy.
7. **Multi-epoch behaviour is untested.** The drill halts at height 16, far inside
   the first epoch (1,152). A halt on an epoch boundary, where the committee roster
   changes at the same height, is a case worth its own drill and is not covered.
8. **🔴 The halt marker is never advanced after a successful resume, so every
   LATER release must keep declaring `resumes_from = 16` forever.** Found in the
   approved resume smoke: after `qumbra-node-resume` carried the node past H, the
   on-disk marker still reads `height = 16, boundary_finalized = true`. The gate
   asks "does this binary declare `resumes_from == marker.height`?", so the *next*
   release after the upgrade — one with no halt of its own and no relation to the
   height-16 boundary — is refused with `UndeclaredResume { marked: 16 }`.
   Verified by running the plain v1.0 binary against the resumed data dir.

   For **this** baton that is correct and even desirable: refusing to downgrade a
   resumed node past its upgrade boundary is exactly what the marker is for. It
   becomes a problem the **second** time the mechanism is used, i.e. on a chain of
   upgrades. Options, none of which this baton should pick unilaterally: rewrite
   the marker on a successful resume to record "resumed past 16 under v1.0.1" and
   match on that instead; accept any release whose revision differs from the
   marker's; or require each release to carry the boundary history. Flagged for the
   coordinator, deliberately not fixed here — choosing wrong would be worse than
   naming it.

   **DECIDED by the coordinator, filed as
   [#81](https://github.com/lai3d/qumbra-lab/issues/81), and explicitly not this
   baton's to build:** the marker will record the frozen digest in force and the
   gate will key on **digest equality**, with height kept as the audit record. The
   gate's real question was never "which height did this node halt at" but "is this
   binary's frozen parameter set the one this chain is running" — and since most
   releases move no frozen constant, an ordinary bug-fix release digests identically
   and simply starts. #81 is gated to land before any real halt-height upgrade after
   the drill.
9. **A node that voted on the old branch cannot vote for the new one at the same
   slot.** The never-double-sign ledger is doing its job, but it means a committee
   member who mined past H on the old binary and voted there has burned those slots
   for the upgraded branch. This is correct behaviour and an argument for halting
   *before* forking rather than mining through — worth a line in the operator
   procedure, which it has.
