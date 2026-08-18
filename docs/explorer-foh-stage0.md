# Explorer front-of-house — stage 0: survey, route proposals, page IA (lab #486)

> [中文版](explorer-foh-stage0-zh.md)

**Status: PROPOSED (2026-08-18) — stage-0 survey deliverable for
[#486](https://github.com/qumbra-labs/qumbra-lab/issues/486). No behavior changes in this
baton; code = none (route stubs deliberately not taken — §7 states why). The route table in
§3 and the IA in §5 are the objects the coordinator reviews.**

Facts verified against lab `main` `31e0cbd`, `qumbra-explorer-web` `667bc61`, and the live
public endpoint `explorer.qumbra.org` sampled 2026-08-18 15:53–15:59 +08. Estimates are
**Claude session-hours** (sh); wall-clock depends on session spacing.

---

## 1. Inventory — what the API serves today

Three routes, `GET`-only, everything else a typed 404/405
(`crates/qumbra-explorer/src/http.rs:1-11`):

| route | document | source |
|---|---|---|
| `/v1/health.json` | the chain-health projection, `HEALTH_VERSION = 1` (`src/json.rs:54`) | `qlab_node::Telemetry`, re-serialized by the run loop (`src/main.rs:176-193`) |
| `/v1/txlist?from=&to=` | the #326 tx-existence view, `TXLIST_VERSION = 1` (`src/txlist.rs:92`) | `TxListView` projected from `node.state().chain()` (`src/main.rs:131-132`) |
| `/healthz` | `"ok"`, no state | — |

`health.json` fields (all from `src/json.rs:65-104`): `v` · `genesis_file_hash` ·
`refresh_secs` · `chain{tip_height, tip_difficulty, regime, peers, mempool}` ·
`finality{head1{height, checkpoint_id, age_s, stall_depth}, head3{state, height, block_hash},
agreement{divergent, token, tracker, durable}}` · `committee{epoch, roster, active, quorum}` ·
`supply{coverage, epochs[]}` — each epoch row already carries `burned`
(`src/json.rs:187-199`, landed as #367 arming prep). Refusal disciplines are inherited whole
from `Telemetry` (`age_s` string with `-`, `epochs` key absent under partial coverage,
`UNAVAILABLE`/`DIVERGENT`/`KNOWN_SCAR` tokens — `src/json.rs:22-42,159-223`).

`txlist` per block-with-transactions: height + per-tx `{txid, wire_bytes, fee, nullifiers,
commitments}` (`src/txlist.rs:134-151`), paged at `MAX_TXLIST_HEIGHTS = 1024` /
`MAX_TXLIST_TXS = 256` with explicit `covered_to` (`src/txlist.rs:111,126`), D3's boundary
sentence served in-band (`src/txlist.rs:96-100`). No lookup by txid — D2, structural
(`src/lib.rs:29-35`).

**Verified against the task-book's premises:** the API half does live in `qumbra-explorer`
(21 crates in `crates/` at `31e0cbd`, not the workspace brief's 17); the page half is
`qumbra-explorer-web` (read, untouched); `health.json` and the #326 view are as the tracker
describes. One premise needs a correction: **the tracker's "boundary crossing is THIS
THURSDAY" does not hold at the target block time** — §6.

## 2. Inventory — what the observer already holds but does not serve

The keyless observer (`RunningNode`, composed at `src/main.rs:112`) applies full blocks and
persists them. In its state today, unserved:

| held state | where | serving status |
|---|---|---|
| **Full header chain**: per height `prev, height, timestamp, difficulty, nonce, tx_body_commitment` | `qlab-devnet/src/header.rs:56-73`; main chain enumerable ascending via `ChainState::main_chain()` + `header(&hash)` (`qlab-devnet/src/chain.rs:286,250`), reachable as `state().chain().chain()` (`qlab-node/src/store.rs:350`) | **unserved** — only `tip_height`/`tip_difficulty` reach `health.json` |
| **Full block bodies for every applied height** (never pruned: `store.rs:334,439`), incl. per-block coinbase value (bessel) | `StoredBlock` (`qlab-node/src/store.rs:153-163`), `block(&hash)` (`store.rs:458`) | unserved (only epoch aggregates via supply rows) |
| **Name-service riders, persisted per tx** — `Commit{commit}` / `Reveal{record, salt}` / `Renew{name}` | `StoredTx.rider` (`store.rs:100-108`); op shapes `qlab-devnet/src/names.rs:162-172`; `NAME_RULE_BOUNDARY_HEIGHT = Some(19_008)` (`names.rs:59`, test-locked `names.rs:615`); folded into `NameRegistry` at `qlab-node/src/node.rs:1591-1595` | **unserved by the explorer** (the node/cbserver `/v1/names?from=&to=` projection — `qlab-node/src/rpc.rs:1012-1024`, `names_page` `rpc.rs:1433` — is a different surface, and a shape R4 can mirror) |
| **Finalized-checkpoint history** (head #1 tracker): ascending `Vec<Checkpoint{height, block_hash, root}>` | `qlab-devnet/src/finality.rs:74-78`; `Checkpoint` at `qlab-devnet/src/committee.rs:177-184`; **reachable** from the explorer via `p2p().node().finality()` (`qumbra-node/src/run.rs:913`, `qlab-p2p/src/adapter.rs:935`) | unserved and **unenumerable** — the tracker exposes only `latest()`/`count()` (`finality.rs:142,198`), no iterator; **process-lifetime** — restart rehydrates from exactly one checkpoint (`finality.rs:93-94`, `adapter.rs:648`); the devnet Vec is unbounded (the `~144 roots` bound noted in `finality.rs:75-76` is not implemented — pre-existing, #135-adjacent, flagged not fixed) |
| **Genesis network label** | `GenesisFile.network: String` (`qumbra-node/src/genesis.rs:368`, `[devnet-placeholder]`, not consensus; the t0 generator writes `"qumbra-devnet-t0"`, `genesis.rs:458`); the explorer already loads the file (`src/main.rs:83`) | unserved — `genesis_file_hash` is the only net identity on the wire today |
| **Peer count / vitals over time** | **does not exist anywhere** — `Telemetry.peer_count` is instantaneous; no timestamped series in `qlab-node`/`qumbra-node`/`qumbra-explorer` (the metrics `Histogram`s aggregate, they do not retain samples — `qlab-node/src/metrics.rs:101`) | needs a new (bounded) projection |

Also held and unserved, but not needed by #486's seven items (named so the route table's
omissions read as choices): the per-round diagnostics ring — populated on a keyless observer,
`RoundLedger.recent`, 64 records with vote/variant/timing detail (`qlab-node/src/round.rs:603,95,942`);
the live peer list (`PeerInfo` per peer, `qlab-p2p/src/peer.rs:113-120`); the whole
`FrozenParams` table + release/revision identity (`genesis.rs:115-217`,
`qumbra-node/src/release.rs:221-231` — a future `/v1/params` could serve these verbatim);
`Telemetry.signed` (sslot/sid) and `supply_lag()`; and the full Prometheus gauge set, renderable
in-process without a listener (`run.rs:1736`).

So of the seven scope items: **four are pure serving additions over already-persisted chain
state** (block ticker, difficulty/interval charts, name feed, banner label), **one is already
fully served** (supply panel — page work only), and **two need a small new projection**
(finality ticker: history exists in memory but needs an accessor or an explorer-side ring;
peer-count-over-time: needs a sampling ring, nothing exists).

## 3. Route proposals

Versioning posture, stated once and proposed as this surface's law: **the explorer's JSON is
its own public surface, deliberately not `RPC_VERSION`** (`src/json.rs:44-54` already records
this). Each document carries its own version const. **A pure addition — a new route, or a new
key in an existing document — does not bump any version** (precedent: `burned` rode into
`supply.epochs[]` rows with `v` staying 1; the reader ignores unknown keys and rejects unknown
`v`). A rename, removal, or semantic change to an existing key bumps that document's version,
which darkens older pages by design (reject-unknown). **Corollary, made binding by the §6
finding:** every additive change refreshes the cross-repo golden corpus
(`crates/qumbra-explorer/goldens/` → `qumbra-explorer-web/fixtures/`) in the same baton — the
corpus only catches skew if it is actually copied.

The PR #315 house rule (primary record `qlab-node/src/rpc.rs:113-118`; `RPC_VERSION = 0x06`
at `rpc.rs:135`) is satisfied trivially: **no `qumbra-node` RPC route or byte moves at all**
— every proposal below is served by `qumbra-explorer` from its own observer's state.
`RPC_VERSION` does not move. The one touch outside the explorer crate is R2's additive
accessor (below), which is lab-internal Rust API, not wire.

All routes are range/bulk-served with no by-id, by-name, or by-address form — the D2 /
PR #315-decision-3 correlation-surface rule extends to every new route: asking about one
thing tells the server which thing you care about; ranges do not.

### R1 — `GET /v1/blocks?from=&to=` (scope items 1 + 3: block ticker, difficulty + interval charts)

Pure serving addition; chain-derived; survives restart.

```json
{ "v": 1, "tip_height": 15761,
  "range": { "from": 15700, "to": 15761, "covered_to": 15761 },
  "blocks": [ { "height": 15761, "block_hash": "e0e0…", "timestamp": 1787039600,
                "difficulty": 2837, "body_commitment": "ab31…",
                "txs": 0, "coinbase": 4979012345 } ] }
```

- Source of truth: the main-chain walk over `StoredBlock`s (`store.rs:153-163`,
  `header.rs:56-70`). Every field is consensus-public.
- Paging: the `txlist` contract verbatim — `MAX_BLOCKS_HEIGHTS = 1024`, explicit
  `covered_to`, client pages backward for history (the PR #312 progress-guard shape).
- The page's block ticker reads the tail of this; the difficulty/implied-hashrate chart and
  block-interval distribution are client-computed from `difficulty` and consecutive
  `timestamp` deltas — **no server-side chart data, no new projection, no ring**. Implied
  hashrate is presentation (difficulty ÷ target interval), computed page-side and labelled
  as implied.
- `coinbase` is the committed per-block value (`store.rs:156`) — this is also what makes the
  supply story per-block-visible ("coinbase presence" in the tracker's item 1; post-mint every
  main-chain block carries one, so the interesting rendering is the value, and post-19,008 the
  value net of name burn).
- New document ⇒ `BLOCKS_VERSION = 1` + two goldens (typical range, empty-covered range),
  both copied into the web corpus.

### R2 — `GET /v1/checkpoints` (scope item 2: finality ticker)

The history exists in `FinalityTracker.finalized` (`finality.rs:74-78`) and the tracker is
already reachable from the explorer process (`p2p().node().finality()` —
`run.rs:913` + `adapter.rs:935`) — but it is **unenumerable**: the tracker's public surface
is `latest()`/`count()` and friends (`finality.rs:142,198`), no iterator over the Vec. Two
options, **(a) proposed**:

- **(a) one additive method on `FinalityTracker`** (qlab-devnet, lab-internal Rust API,
  additive, no wire, no RPC): `finalized_tail(n) -> &[Checkpoint]` (or an iterator), the last
  `n` in ascending order. The explorer serves the tail through the accessor chain that
  already exists.
- (b) explorer-side ring fed by observing `telemetry().finalized_id` transitions in the run
  loop. Rejected as primary: it can only see checkpoints that were the head at a loop tick,
  and it is a second copy of state the node already holds.

```json
{ "v": 1, "history_from_height": 15320,
  "checkpoints": [ { "height": 15720, "block_hash": "e0e0e41fc07a", "fid": "3ba08370682f",
                     "span": 8 } ] }
```

- Served bound: last `MAX_CHECKPOINTS = 512` (~2.8 days at the 8-block cadence), a serving
  bound regardless of the tracker's growth. `span` = height delta from the previous finalized
  checkpoint (the Ebb-and-Flow story: span > cadence means degraded time was crossed).
- **Honesty field `history_from_height`**: the tracker rehydrates from one checkpoint at
  restart (`adapter.rs:648`), so depth is process-lifetime. The document says where its
  history actually begins; the page renders "since the observer last restarted" rather than
  implying chain-lifetime history.
- `slot` is not retained per historical checkpoint today (only the live head's `sslot` in
  telemetry); the ticker ships without it rather than growing node state — noted as the one
  divergence from the tracker's "(fid, slot, span)" wish. If slot is wanted, that is node-side
  retention and a stage-1 question on the issue, not silently added.
- Not proposed: persisting the ring. Bounded-memory is law (#135); a restart-gap in a ticker
  is honest and cheap, a second persistence format is neither.

### R3 — `GET /v1/vitals` (scope item 4: peer count + net vitals over time)

The one genuinely new projection: a sampling ring in the explorer process (nothing holds this
anywhere today).

```json
{ "v": 1, "sample_secs": 60, "since": 1787000000,
  "samples": [ { "t": 1787039640, "peers": 5, "mempool": 0, "tip_height": 15761,
                 "stall_depth": 0 } ] }
```

- The run loop (`src/main.rs:176-193`) already ticks continuously; it appends one sample per
  `sample_secs` from the same `Telemetry` snapshot it already takes.
- **Bound: `VITALS_SAMPLES = 1440` × 60 s = 24 h**, ≈ 1440 × 40 B ≈ **58 KB resident**,
  fixed — proposed as the #135 bound. Document worst case ≈ 120 KB JSON, served whole (no
  paging needed at this size).
- Process-lifetime, `since` says so (same honesty rule as R2). Not persisted, same grounds.

### R4 — `GET /v1/names/events?from=&to=` (scope item 6: name-event feed) — §4 has the full design

Pure serving addition, chain-derived from the persisted riders (`store.rs:100-106`) — **not**
a ring, which is what makes the dark-ship work (§4).

### Already served — scope item 5 (supply attestation panel)

**No API change.** `supply.epochs[]` already carries `expected_coinbase`,
`measured_coinbase`, `fees`, `burned`, `delta`, `verdict` per epoch
(`src/json.rs:183-215`), including the `KNOWN_SCAR` grandfathering. The emission schedule the
panel compares against is deterministic and the rows already carry both sides. Item 5 is
page work: render the panel, add the `burned` column (currently absent from the page —
`qumbra-explorer-web/index.html:136-148` has no burned column), with the "goes non-zero with
name registrations" copy. Plus the fixture refresh §6(b) owes.

### Additive field — scope item 7 (TESTNET banner's net-name source)

`health.json` gains one top-level key, additive, `v` stays 1:

```json
"network": "qumbra-testnet-t1"
```

- **Source: `GenesisFile.network` verbatim** (`genesis.rs:368`), which the explorer already
  loads at startup (`src/main.rs:83`). Chain-pinned — a node refuses to boot against a
  genesis-file-hash mismatch, so the label cannot drift from the net actually observed —
  and never hardcoded in the page. (The exact string the live T1 genesis carries was not
  read in this baton — genesis files are on the workspace's no-read list; the field's
  existence and load path are verified in code. Stage 1 renders whatever it says.)
- Page rule (stage 2): the banner renders whenever `network` is not the reserved mainnet
  label (proposed literal: `qumbra-mainnet`, decided at mainnet-genesis time); an absent key
  (older API) renders the banner with an "unidentified net" state rather than hiding —
  fail-loud, per naming-and-branding §7's intent (nobody mistakes a testnet for the money
  net). Suppression is the exception, never the default.
- §7's tagged zone (`explorer.t1.qumbra.org`) does not resolve yet (checked 2026-08-18; the
  execution rides the T2 batch per the design doc) — the banner must not depend on the
  hostname, which is one more reason the label comes from genesis, not the URL.

## 4. The name-event feed's dark-ship design (scope item 6)

**Data path.** Post-19,008, v3 bodies carry per-tx riders and the observer persists them
(`store.rs:100-106`). The feed is a projection over the main-chain walk, exactly like
`txlist`: decode each stored tx's rider (`names.rs:278` `decode_rider`), emit events.

```json
{ "v": 1, "boundary_height": 19008, "tip_height": 15761,
  "range": { "from": 15000, "to": 15761, "covered_to": 15761 },
  "events": [
    { "height": 19012, "kind": "commit", "commit": "9a4f…" },
    { "height": 19031, "kind": "reveal", "name": "larry", "record_kind": "l1_address",
      "fee_burned": 12800000000, "expires_height": 33111 },
    { "height": 19400, "kind": "renew", "name": "larry", "fee_burned": 12800000000 } ]
}
```

- **Commits render as what they are**: an opaque `H(record ‖ salt)` (`names.rs:163-165,356`)
  — the honest copy is that a commit proves someone reserved *something*, revealed within
  the `[8, 2304]`-block window (`names.rs:81-83`). No fake decode, no "pending name".
- **Reveals are the first user-visible proof the name service exists**: name (N3 grammar,
  ≤63 bytes), record kind, and the burned fee by length tier (`names.rs:103`
  `name_fee_bessel` — 1/32/128/512/2048 QMB) — which is also the moment the supply panel's
  `burned` column goes non-zero, and the two surfaces corroborate each other. **The bound
  address is deliberately omitted from the feed document**: a reveal's wire also carries the
  1,233-byte L1 address (`names.rs:150-156,94`) — consensus-public, already servable via the
  node's `/v1/names` rider projection (`rpc.rs:1012-1024`) — but an *event feed* answers
  "what happened", not "resolve this name", and carrying ~1.2 KB per reveal would make the
  feed's weight the address book's. A reader who wants the binding has the other surface.
- **Renews** are public consensus events too (`names.rs:169-171`) and ride the same feed —
  the tracker says "commits and reveals"; renew is included because omitting a third public
  op kind from an event feed would be a silent editorial choice. Flagged as a small scope
  extension for the coordinator to strike if unwanted.
- **Before the boundary: an honest empty state, not a fake.** The document always carries
  `boundary_height` (from `NAME_RULE_BOUNDARY_HEIGHT`, `names.rs:59`); pre-boundary the
  events list over any covered range is empty *and the page says why*: "The name service
  arms at height 19,008 — every registration will appear here from its first block." An
  empty-covered range is a fact, not an error (the `txlist` empty/covered distinction,
  `src/txlist.rs:716` test, reused verbatim).
- **The timing pressure is softer than the tracker states, and this is a finding, not a
  reason to slow down:** because the feed is projected from *persisted chain state* rather
  than accumulated in a ring, it **backfills** — an explorer rolled after the boundary still
  serves every event from block 19,008 on next walk. "The API shape should land in stage 1
  so the data accrues from block one" is therefore automatically satisfied by construction;
  what landing early actually buys is the page having something to point at the moment the
  boundary crosses, which is still worth sequencing R4 first in stage 1.
- No resolve-by-name, no name→history lookup: range-served only, matched client-side if the
  page grows a filter (the D2 rule; the node's own `/v1/names` route already refuses
  resolve-by-name by name, per the #381 record).

## 5. Page IA sketch (stage 2 — `qumbra-explorer-web`, honoring zero-build)

Constraints honored: vanilla ES modules, no framework, no build, no external reference;
`contract.js` decides / `app.js` draws (`README.md:29`); bilingual in-DOM; banner mechanism
and severity classes already exist (`assets/app.css:134-153`). **Charts are hand-rolled
inline SVG emitted by a new pure module `charts.js`** (string-in → SVG-string-out, tested
under `node --test` like `contract.js`; no `<canvas>`, no library). The split-decision doc
names "the page needs time series" as the honest trigger to re-open its axis 3
(`t1-explorer-split-decision.md` §3) — position taken here: **axis 3 does not re-open**,
because the trigger's substance was "a charting library is a real dependency", and ~150
lines of hand-emitted SVG polyline/histogram is not a dependency. If the coordinator reads
the trigger literally instead, that is a one-line ruling to ask for on #486 before stage 2.

```
┌────────────────────────────────────────────────────────────────┐
│ ⚠ TESTNET — qumbra-testnet-t1 — coins have no value            │  ← NEW banner, above topbar,
│   (label from health.json "network"; never hidden on testnet)  │    amber .banner.warn, both langs
├────────────────────────────────────────────────────────────────┤
│ topbar: mark · Qumbra · [中文] [◐]                              │  (unchanged)
│ h1 Chain health — lede (unchanged)                             │
│ #status banner (unchanged)                                     │
├── Chain ───────────────────────────────────────────────────────┤
│ tip · difficulty · regime · peers · mempool (unchanged table)  │
│ NEW  Live blocks: last 12 of R1, newest first, rolling on poll │
│      height · age · txs · coinbase · body commitment (short)   │
├── Finality ────────────────────────────────────────────────────┤
│ existing head1/head3/agreement table (unchanged)               │
│ NEW  Checkpoint ticker: last 8 of R2 — height · fid · span     │
│      + "history since observer restart at #15320" honesty line │
├── NEW Work (charts, all client-computed from R1) ──────────────┤
│ difficulty over height (SVG line) + implied hashrate label     │
│ block-interval distribution, last 1024 (SVG histogram)         │
│   caption: "LWMA targets 75 s; spread is ordinary PoW variance"│
├── NEW Network (from R3) ───────────────────────────────────────┤
│ peers over 24 h (SVG line) · mempool sparkline                 │
│   + "sampled every 60 s since observer start" honesty line     │
├── Committee ──────────────────────────── (unchanged) ──────────┤
├── Supply attestation ──────────────────────────────────────────┤
│ existing table + NEW burned column                             │
│ NEW note: "burned goes non-zero with name registrations"       │
├── Transactions ────────────────────────── (unchanged) ─────────┤
├── NEW Names ───────────────────────────────────────────────────┤
│ pre-19,008: "The name service arms at height 19,008. Commits   │
│   and reveals are public consensus events and will appear here │
│   from their first block. Empty now — by design."              │
│ post: event feed (R4), newest first: commit = opaque hash with │
│   the honest explainer; reveal = name · kind · fee burned      │
├── footer ──────────────────────────────────────────────────────┤
│ existing wall paragraph + NEW sentence (product copy, both     │
│ langs): "No balances, no addresses, no transaction graph —     │
│ not missing, absent by design: the chain does not carry them." │
└────────────────────────────────────────────────────────────────┘
```

The wall's absences move from footer-only to **stated on the page where a reader would look
for the missing thing** — the Names section explains commits are opaque *because that is the
protocol*, and the footer sentence is tightened to the proposed product copy above ("no
balances — by design" is the tracker's phrase, rendered in full sentences).

## 6. Findings (stage-0 side-finds, none fixed here)

**(a) 🔴 The live `health.json` is frozen while the same process's `txlist` advances.**
Observed 2026-08-18 15:53–15:57 +08, reproducible across four fetches: `health.json` pinned
at `tip_height 15727, age_s "491", stall_depth 7` byte-identically, while `/v1/txlist`
reported `tip_height 15761` — the health document is ≥34 blocks (~42 min at target) stale
and its frozen `age_s` proves it is not being re-serialized at all (the `refresh_secs`-floor
re-render should move `age_s` every ≤30 s). Both views are updated by the *same* run-loop
closure (`src/main.rs:176-193`), so the loop runs; the suspect seam is the health write
specifically: `if let Ok(mut p) = page.write() { … }` (`src/main.rs:181-183`) **silently
swallows a poisoned/failed `RwLock` forever, with no log line** — one panic in a writer at
any point in process history darks the projection permanently while `/healthz` keeps
answering `ok`. Hypothesis, not diagnosis: no host access from this seat (and none sought —
deploy is out of scope). Whatever the root cause, stage 1 should (i) replace the silent
swallow with a loud log + `/healthz` degradation, and (ii) the ops side may want to bounce
the explorer container now — T-ops' call, flagged on #486.

**(b) 🟡 The cross-repo golden corpus has already skewed.** Lab goldens carry `"burned":0`
in every supply row (`crates/qumbra-explorer/goldens/agreed` etc., since the #367 arming
prep); `qumbra-explorer-web/fixtures/{agreed,durable-lag,durable-absent}` do not — the
fixtures were never refreshed, so the corpus's "a rename turns one side red" property is
currently not in force for the three health goldens (both suites are green against their own
stale copies). Stage 2 refreshes the fixtures; §3's versioning posture makes the same-baton
refresh binding so this class closes.

**(c) 🔴 The served tip did not advance for ≥10.8 minutes** (`txlist.tip_height` pinned at
15,761 across 4 samples, 15:54:44–16:05:30 +08). At the 75 s target a zero-block 646 s
window has p ≈ 0.02% on a healthy net — so either the T1 net's tip is genuinely stalled, or
this observer is desynced from it; this seat cannot distinguish the two (no fleet access,
none sought). Sequence note: the health document froze at tip 15,727 (§6(a)), the txlist
view then advanced 34 more blocks to 15,761 and stopped — so the process was still applying
blocks *after* the health freeze, which reads as either a progressive wedge of the observer
or two independent events (health-write failure + a later net stall; the frozen snapshot's
own `stall_depth 7 / age_s 491` already showed finality stalling). For T-ops correlation,
flagged on #486.

**(d) `explorer.t1.qumbra.org` does not resolve yet** (naming-and-branding §7's execution
rides the T2 batch) — recorded so stage 2 doesn't assume the tagged hostname.

**(e) `FinalityTracker.finalized` is unbounded on devnet** (`finality.rs:75-76` notes the
~144-root bound as not-implemented). ~2.4 K entries at current height — harmless today,
pre-existing, #135-adjacent; R2 serves a bounded tail regardless. Named so nobody mistakes
R2 for the thing that needs the bound.

**(f) Lab `CLAUDE.md` drift: the #381 entry still says `NAME_RULE_BOUNDARY_HEIGHT = None`
("merged inert")**, while the shipped constant is `Some(19_008)` (`names.rs:59`, test-locked
at `names.rs:615`). True at the #381 merge, stale since arming. One-line doc fix, not taken
here (out of this baton's scope).

## 7. Why no route stubs in this PR

The task-book allows "at most route stubs behind tests". Deliberately not taken: a stub that
serves a versioned empty document would put `v:1` bytes of four new contracts on a public
surface before the coordinator has reviewed the §3 shapes — and this surface's whole
versioning posture is that served bytes freeze deliberately. Stage 1 lands each route whole
(projection + goldens + web-corpus copy) instead.

## 8. Stage plan (estimates in Claude session-hours)

| stage | content | est |
|---|---|---|
| **1 — API** (lab `qumbra-explorer`, one baton) | R4 first (name feed, so the page has it at the boundary), then R1, the `network` field, R2 (with the additive tracker accessor), R3; goldens for each + web-corpus copies; the §6(a) silent-swallow fix rides along (same file, precondition-adjacent — flagged in the PR if folded) | 3–4 sh |
| **2 — page** (`qumbra-explorer-web`) | banner + Names section + Live blocks + checkpoint ticker + `charts.js` (SVG, pure, tested) + Network section + burned column + copy (EN/ZH) + fixture refresh (§6(b)) + publish-manifest/test updates | 3–4 sh |
| **3 — roll** | svc0 image roll (T-ops, ordinary; explorer API first, page second — the page tolerates missing routes by rendering its named UNAVAILABLE state, `app.js:233-236` precedent) | outside these estimates |

Boundary arithmetic for sequencing: live tip 15,761 at 15:54 +08 2026-08-18; 19,008 − 15,761
= 3,247 blocks ≈ **67.6 h at the 75 s target ⇒ ~2026-08-21 (Friday) midday +08**, not "this
Thursday" as the tracker says — and the served tip is currently not advancing at all
(§6(c)), which can only push it later. Stage 1 comfortably lands before the boundary either
way if dispatched promptly; the correction matters only so nobody treats Thursday as a hard
deadline that would justify skipping review. (And even a missed boundary costs nothing
here: R4 backfills, §4.)

## 9. Decided here vs open for the coordinator

**Proposed:** the §3 route table (R1–R4 + `network` field) · additive-no-bump versioning as
this surface's law + binding same-baton corpus refresh · name feed chain-derived (backfills;
renews included; bound address omitted from the feed) · banner from `GenesisFile.network`,
fail-loud when absent · charts as hand-rolled SVG, axis 3 not re-opened · no stubs in
stage 0.

**Open (asked on #486):** strike renews from R4? · R2's additive accessor seam vs
explorer-side ring · whether historical `slot` is worth node-side retention (R2 ships
without it) · the axis-3 reading if hand-rolled SVG is judged to re-open it · §6(a): bounce
the live explorer now, or wait for the stage-1 fix.
