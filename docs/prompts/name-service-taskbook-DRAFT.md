# Task book DRAFT — the name-service baton (T2; NOT dispatchable)

> Written 2026-08-12, ahead of the T2 gate on the same rationale as the brief itself: T2's
> opening move should be a task book, not a blank page. **Nothing here is dispatchable until
> the T2 gate opens** — the later of (a) the emission boundary passing (✅ 2026-08-12, #299/#303
> closed) and (b) the T1 launch list discharging (⬜ open). Precedent for the DRAFT state:
> `halt-height-taskbook-DRAFT.md`.

Design sources, both STAMPED and binding:
[`name-service-decision`](https://github.com/qumbra-labs/qumbra-design/blob/main/name-service-decision.md)
(D1–D4, Larry 2026-08-10) and
[`name-service-t2-brief`](https://github.com/qumbra-labs/qumbra-design/blob/main/name-service-t2-brief.md)
(N1–N7, Larry-delegated 2026-08-12, on the citation-verified text). This task book adds **no
decisions** — it grounds the stamped design in this tree's real seams, proposes the
boundary-stamped numbers for Larry's dispatch-day stamp, and drafts the byte layout the brief
scoped to "task-book scope". Where the tree contradicts a brief sentence, the correction is
recorded here with a date (one exists: §3).

## 0. Dispatch preconditions (all four, in order)

1. **T2 gate open** — emission boundary passed ✅ AND T1 launch list discharged ⬜.
2. **The survey lands** — the #139 report becomes `name-service-survey-2026-08.md` in the
   design repo with its full source-verification pass (the brief's own 14 citations were
   verified 2026-08-12; the survey's §7 table has not been).
3. **Larry stamps the numbers** (§2 below) on the dispatching issue, exactly as
   `RULE_BOUNDARY_HEIGHT` was stamped at the #299 dispatch.
4. **Larry pastes the opening prompt** to a CLI builder session — consensus baton, not
   Multica (this touches the committed body format and the coinbase value rule; same class
   as the emission-rule baton).

## 1. What this baton builds, in one paragraph

A name (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, no `--` at positions 3–4) rents a binding to
one dedicated diversified address for 365 epochs at a length-tiered burned fee, registered
FCFS through a mandatory commit–reveal riding the ordinary transaction as a versioned
**committed rider** — the circuit never sees it. Records are write-once: no update, no
transfer, no revocation; renewal is permissionless; expiry (plus 90 grace epochs) re-opens
the name, and a re-registration is a wallet **alarm**, not a routine event. Wallets bulk-sync
the registry and resolve locally; there is no resolve-by-name endpoint, ever. Everything
arrives at one halt-height boundary as body format **v3**.

## 2. Numbers awaiting Larry's stamp at dispatch (PROPOSED here, not decided)

| Constant | Proposal | Grounding |
|---|---|---|
| `NAME_RULE_BOUNDARY_HEIGHT` | — | Larry's stamp at dispatch, like #299's. Body v3 + rider validity both key on it |
| `NAME_FEE_BASE` (5+ chars) | **1 QMB / 365 epochs** | 100× the 2×2 relay fee (`fees.rs` 0.01 QMB); spam-filling 1 GB of registry (~750 K records at ~1.34 KB) then burns ~750 K QMB ≈ **13 days of the whole net's launch emission** (~57.5 K QMB/day measured, epoch 0 attestation) |
| `NAME_FEE_4` | 32 QMB | ENS's stamped ratio is the only measured tier structure that visibly cooled short-name bidding: 32× base for 4-char |
| `NAME_FEE_3` | 128 QMB | ENS 128× base for 3-char (same source) |
| `NAME_FEE_2` | 512 QMB | extrapolated 4× ladder — no auction exists (N1), so scarcity is priced by rent alone |
| `NAME_FEE_1` | 2,048 QMB | same ladder |
| `NAME_TERM_EPOCHS` | 365 | stamped in the brief (N6) |
| `NAME_GRACE_EPOCHS` | 90 | stamped in the brief (N6) |
| `COMMIT_MIN_AGE` / `COMMIT_MAX_AGE` | 8 / 2,304 blocks | brief §1 (~10 min / ~2 days at 75 s) |
| Grace-window resolution | **resolves, flagged "expiring"** | the brief leans this way (N6/Decided-vs-open); a dark grace window turns every lapsed renewal into an outage before it becomes a loss |

Renewal extends by whole 365-epoch terms from `max(now, current_expiry)`; renewal price =
the name's current-length tier (no partial terms at v1 — a door, not a wall). Fees are flat
QMB, revisable only at later halt boundaries; the drift-vs-fiat cost is stated in the brief's
honest-tradeoffs register and is not this baton's to solve.

## 3. Dated correction to the brief (2026-08-12, from this tree)

The brief's N2 says burn "needs no new machinery beyond the `SupplyLedger` accounting the
emission gate already added." **The tree says otherwise**: fees are paid to the miner —
`coinbase.rs:138`, `value = RewardSplit::of(body.coinbase).miner + body.total_fees()`, and
`supply.rs`'s module doc states fees "are never burned." Burning the name-fee portion
therefore touches the **coinbase value rule**:

```
value = RewardSplit::of(body.coinbase).miner + body.total_fees() - body.total_name_burn()
```

plus a burn column in `SupplyLedger` and a rewrite of the `supply.rs` sentence that becomes
false. This is still zero circuit work (the declared fee is a public input; the split is
consensus accounting) — N5 holds — but it is a consensus-critical seam adjacent to the one
the emission gate just armed, and the golden that locks `coinbase_value` MUST break and be
legitimately re-derived. The correction is design-doc-owed: a dated block on the brief's N2
when this baton lands.

## 4. The rider byte layout (draft — task-book scope per the brief)

Body format **v2 → v3**: `TxEntry` gains one committed field, `rider: Vec<u8>`, following
`discovery`'s exact discipline — held as bytes, canonicity rule "decode canonically and
re-encode to yourself" (§4 rule 3 precedent), **canonical absence is `[0x00]`, not an empty
Vec** (one way to say nothing). Every existing tx pays 1 byte; the body commitment moves at
v3 (it moves at any format bump); the served `/v1/compact` vectors MUST NOT move — the
two-goldens-opposite-directions check from the #188 mint applies verbatim.

```
rider        := 0x00                                      — no rider (canonical absence)
              | 0x01 ‖ op ‖ op_payload                    — rider version 1, ONE op per tx

op           := 0x01 COMMIT  ‖ commit_hash (32 B)
              | 0x02 REVEAL  ‖ record ‖ salt (32 B)
              | 0x03 RENEW   ‖ name_len (u8) ‖ name

record       := record_kind (u8) ‖ name_len (u8) ‖ name (1–63 B)
                ‖ addr_len (u16 LE) ‖ address (addr_len B)

record_kind  := 0x01  l1-address (~1,233 B, wallet-interop §1)
                — additive-only registry; 0x02 is reserved by the L2 addendum
                  (annulet-address) and MUST NOT be defined by this baton

commit_hash  := Keccak-256("qumbra:name:commit:v1" ‖ record ‖ salt)
```

Notes, each load-bearing:

- **`record_kind` sits inside the commit preimage.** The stamped L2 addendum requires the
  record-kind field from v1; a commit that did not bind the kind would let a reveal swap it.
  This refines the brief's §1 `commit = H(name ‖ address ‖ salt)` by widening `address` to
  `record` — a task-book refinement consistent with the addendum, flagged here rather than
  silently made.
- **Domain-separated preimage** — precedent `b"qumbra:checkpoint:v1"` (`committee.rs`).
- **One op per tx at v1.** Batching is a door; a `Vec<op>` encoding can arrive as rider
  version 2 without a wire redesign.
- **`addr_len` is u16** because 1,233 > 255, and because record kinds may differ in size.
- Rider bytes are priced into block weight (`weight.rs`) like every other body byte — the
  anti-spam penalty applies with no new rule.

## 5. Stages

### Stage 0 — constants (dispatch day)

`names.rs` param block: the §2 table as consts, golden-locked the way the fee table and
emission pins are. Nothing else lands until the stamp comment exists on the dispatching issue.

### Stage 1 — the rider on the wire (body v3)

`TxEntry.rider` + v3 body commitment + canonical encode/decode with the `[0x00]` absence +
golden body-commitment vector (MUST break vs v2, re-derived once, locked) + the
served-vectors-unmoved golden + rider-bytes-in-weight. Both goldens in the same PR, opposite
directions, per the mint precedent. v3 activates at `NAME_RULE_BOUNDARY_HEIGHT` through the
#74/#81 halt-marker machinery — this baton adds **no new upgrade mechanism**.

### Stage 2 — consensus validation (plain code, no circuit)

In `validate_body`, above the boundary only:

1. **Grammar** — the N3 regex as a hand-rolled byte check (no regex dep in consensus), plus
   the `--`-at-3–4 refusal. Test vectors: every ENSIP-15 example that should fail here,
   punycode shapes, `0/o 1/l` confusables (which MUST pass — the residue is D3's to carry,
   test named to say so).
2. **Commit–reveal ordering** — reveal valid iff a matching commit sits in
   `[h − COMMIT_MAX_AGE, h − COMMIT_MIN_AGE]`; outside the window the commit is dead; salt
   reuse across a dead commit is the registrant's loss (stated, not protected).
3. **Uniqueness** — name unregistered or past grace at reveal height. Same-block ties
   resolve by tx order in the committed body (brief §1).
4. **Fee split** — declared fee == `posted_fee(bucket) + name_fee(op, len)`; the name-fee
   portion is burned via the §3 coinbase-value change. COMMIT pays relay tier only.
5. **Renewal** — name exists (registered or in grace), fee covers the tier, extends from
   `max(now, expiry)`. No authorization — extending an immutable binding harms nobody (N4).

### Stage 3 — registry state

`NameRegistry` in `qlab-node`: a replay of committed riders over the main chain, snapshot +
replay + **reorg handling on the `SupplyLedger` precedent** (its reorg gap was paid for once,
PR #325 — copy the shape, not the lesson). Expiry is a **pure function of height** — no
state mutation happens at expiry; resolution checks `expiry + grace` at read time.
`audit-names`: a read-only reconstruction tool on the `audit-emission` pattern (exit codes
0/1/2, `--from --to`), reconciling registry state and total burn against the committed
riders. Every consensus change in this repo since #299 has shipped with its auditor; this
one does too.

### Stage 4 — burn accounting

The §3 coinbase-value change + `SupplyLedger` burn column + supply attestation extension
(explorer/opview show cumulative name-burn beside fees; the `supply.rs` "never burned"
sentence rewritten). The attestation stays integer-exact, tolerance zero.

### Stage 5 — serving (D2 at the route level)

`GET /v1/names?from&to` — per-block, bulk-only-by-shape, paged per the #312 contract, a pure
route addition (no `RPC_VERSION` bump, per the PR #315/#317 house rule). **No name-keyed
route exists**, and a test asserts the refusal by name — D2 enforced at the route level,
the #315 nullifier precedent applied the fourth time. Completeness comes from block
coverage: a lying-by-omission server must omit whole blocks and be caught by the header
chain; **no new state commitment at v1** (brief N5 — a stop point below).

### Stage 6 — wallet

Registry bulk-sync + local resolve (through the paging guard — the #312 lesson says a
truncated range must never read as `complete`) · pins store `names-pins.v1` (the
`contacts.v1`/`sends.v1` pattern: local, versioned, reject-unknown) · `register` command
driving commit → wait → reveal as a resumable state machine (salt persisted BEFORE the
commit tx posts — the #324 lesson: write the local record before the network can answer) ·
`send --to alice.qmb` (bare label = `.qmb` display convention; resolution is local; the
`qs1…` fingerprint prints beside every resolution, D3 unchanged) · the **rebind alarm**: a
resolution whose address differs from the pin refuses loudly until re-confirmed out of band
(N6's known_hosts rule, normative) · grace-window records resolve flagged "expiring".
`qumbra-ffi` surface for names is explicitly **not** v1 (iOS reads the door, not this baton).

### Stage 7 — drills (before the boundary arms on any live net)

1. **Halt-boundary activation drill** — the i299 §5–7 shape: arm, halt, adjudicate the
   boundary fid, resume with v3 bodies. The 8,640 boundary's three defects (#360, the tip
   tie, #362) are all fixed on main; this drill proves them fixed **at a boundary that
   changes the body format**, which 8,640 did not.
2. **Front-run race** — an adversary node sees a reveal in the mempool and races its own
   commit+reveal; the original's earlier commit MUST win. Mutation-check: disable the
   window check and the test must fail.
3. **Expiry snipe e2e** — register, lapse past grace, adversary re-registers, victim's
   wallet MUST refuse payment with the rebind alarm until re-confirmed.
4. **Reorg across a registration** — the #325 SupplyLedger reorg shape, applied to a
   registration that un-happens and re-happens on the winning fork.
5. **Grammar fuzz** — round-trip canonicity on random riders; any decode that re-encodes
   differently is a fail.

## 6. Stop points (stop and report on the dispatching issue, never proceed)

- Anything that would touch `qlab-air` or the proof statement. N5's whole shape exists so
  this never happens; if a seam seems to require it, the design is being misread.
- Any change to `RewardSplit`, the emission schedule, or `coinbase_exact` beyond the §3
  subtraction. The emission gate is armed and live; its goldens are load-bearing.
- Any grammar wider than N3's. Widening is a **versioned door at a later boundary**, not a
  builder judgment call.
- Any name-keyed query surface, on any route, however convenient for debugging (D2 is
  permanent; the refusal test in Stage 5 is the wall).
- Any registry state commitment in headers or consensus. Explicitly deferred by the brief;
  proposing one re-opens N5 and is Larry's to re-open, not this baton's.
- A same-height fid split or finality regression during the Stage 7 boundary drill — R2,
  the OPERATOR.md §7 stop, evidence preserved before anything is touched.

## 7. Acceptance (what the coordinator will run)

The full unfiltered workspace suite, serial, rig-locked (`scripts/rig run -- cargo test
--release --workspace -- --test-threads=1`), arithmetic reconciled to the function against
main's spine (1,535/0/7 as of 2026-08-12). Goldens: body-commitment moved once and locked;
served vectors unmoved; coinbase-value golden re-derived once with the burn subtraction.
End-to-end on a devnet: register → sync → resolve → pay → renew → lapse → snipe → alarm.
Negative greps zero. Estimate stands at the brief's **15–40 session-hours + one halt-height
boundary of T-ops time**; stages 1–4 are the consensus half (~60 %), 5–6 the serving/wallet
half, 7 runs against both.
