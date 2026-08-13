# Name-service boundary — arming procedure (lab #367)

> [中文版](name-boundary-arming-zh.md)

**Status: PREPARED AHEAD — not executable until the T2 gate opens** (T1 launch
list [#370] discharged; the gate's emission half passed 2026-08-12). Written
while the machinery is fresh from boundary day, on the `i299-emission-boundary-activation.md`
model, so arming day is a checklist and not an archaeology dig. The construction
this activates merged inert as PR #381; [#367] is the tracker this document
belongs to.

[#370]: https://github.com/qumbra-labs/qumbra-lab/issues/370
[#367]: https://github.com/qumbra-labs/qumbra-lab/issues/367

## 0. What is changing, in two sentences

Above `NAME_RULE_BOUNDARY_HEIGHT`, transactions may carry a **name rider**
(commit / reveal / renew), the block body commits under the **v3 encoding**
(the first body-format change to arrive over a halt boundary rather than a
re-mint), and the name-fee half of a registering transaction's declared fee is
**burned** — subtracted from the coinbase note, reported in the supply
attestation's `burned` column. Below the boundary — the entire chain until
arming day — nothing changes, which is the property `commitment_at_with_no_boundary_is_v2_everywhere`
locks.

## 1. Preconditions (all SIX, in order — none is a formality)

1. **The T2 gate is open**: the [#370] checklist is discharged and T1 public
   mining has been running long enough that FCFS registration is fair — the
   fairness argument (pre-public registration is insider-only registration) is
   recorded in [#367]'s early-activation discussion and is a Larry call, not an
   ops judgment.
2. **[#375] is fixed and its test merged** — the frozen-boundary tie's losing
   side finalizing a checkpoint it does not hold was found ON boundary day and
   must not attend the next one.
3. **The [#369] standing drill exists and covers a BODY-FORMAT boundary** — the
   8,640 halt changed a validation rule; this one changes the wire. The drill
   must run a committee to a halt across a v2→v3 body switch in-suite (the
   `validate_body_above` / `commitment_above` seams exist for exactly this).
4. **The `0x06` telemetry wire is deployed fleet-wide** (this PR's bump: the
   `burned` tail + explorer column). Roll it with any ordinary image refresh —
   it is inert data plumbing; `READABLE_TELEMETRY_VERSIONS` keeps opview sighted
   during the roll. Verify: `curl explorer/v1/health.json | jq '.supply.epochs[0].burned'`
   answers `0`, not `null`.
5. **Larry stamps the boundary height on [#367]** — a halt-height comfortably
   ahead (the 8,640 re-stamp gave ~4.5 h of runway and it was enough only
   because three defects got fixed live; give this one ≥2 days), at an epoch
   boundary if convenient but nothing requires it.
6. **Fee table re-ratified at the stamp** — the constants merged 2026-08-12
   (1/32/128/512/2048 QMB by length, 365+90 epochs, 8/2,304 window). If QMB's
   purchasing reality moved since, this is the moment to restate or restamp;
   after arming they move only at later boundaries.

## 2. Step 0 — stamp the constant and flip the goldens

On a worktree from current `main`:

- `NAME_RULE_BOUNDARY_HEIGHT: Option<u64> = None` → `Some(<stamped height>)`
  (`crates/qlab-devnet/src/names.rs`).
- The inert-at-merge tests **must now fail and be retired in the same commit**,
  replaced by their armed duals (each names its replacement in a comment):
  `commitment_at_with_no_boundary_is_v2_everywhere` → the boundary-split
  golden; `validate_body_rider_leg_end_to_end`'s shipped-rule
  `CommitmentMismatch` case → the armed happy path.
- Re-derive the v3 body-commitment golden AT the stamped boundary (the
  drill-seam golden at `Some(8_640)` stays as the format lock; the shipped-rule
  golden moves once, legitimately, and is locked).
- `qumbra-node halt-status` must banner the name boundary the way it banners
  the emission one — if it does not, that seam is owed BEFORE images build.

Acceptance for step 0 = the full suite on `suite-arm64` (heavy runs stay off
the laptop — standing rule since 2026-08-12), arithmetic reconciled.

## 3. Build both images before rolling either

The i299 pattern verbatim (`deploy/docker`, `NODE_FEATURES` build-arg pattern
if a feature split is used; otherwise two tags off the two commits):

- **armed** — halts at the stamped height, banner says so;
- **resume** — v3-capable past the boundary, banner says so.
- **Push resume FIRST** (the i299 rule: the image you need in an emergency is
  the one that must already be on GHCR).

## 4. Roll the armed image — ALL SIX hosts

node0–3 **and svc0/svc1** (the 8,640 lesson: the svc hosts predate a boundary
at their peril — the explorer observer stuck at `halted 8640` for a day was
this exact omission). One host at a time, `slag=0` rejoin verified per host,
R2 guard (same-height fid split) watched throughout — OPERATOR §3/§7 govern.

## 5. The halt, the boundary fid, the resume

i299 §5–6 verbatim, plus the two boundary-day fixes this time arrive
pre-merged (#360 halted-proposal maintenance, #362 REPUSH cadence):

1. Net halts at the stamped height; every host banners the halt.
2. **Coordinator adjudicates the boundary fid: 3-of-4 minimum, one identity**
   — a split here is R2, stop everything, preserve state.
3. Resume waves per §6 (parallel where the runbook says so), svc hosts in the
   same wave set.
4. Chain resumes; first post-boundary checkpoint finalizes under v3 bodies.

## 6. Verify the rule actually bound (the §7 discipline)

- `qumbra-node audit-names --data-dir <dir> --from <boundary+1>` → **exit 0,
  registry AGREES** — on ≥3 hosts independently.
- `audit-emission --from <boundary+1>` → exit 0 (the burn must not have bent
  the emission rule: coinbase still exact, fees split correctly).
- `GET /v1/names?from=<boundary>&to=<tip>` through the public edge → 200,
  decodes, riders present where expected.
- `GET /v1/names?name=probe` → **400 with the D2 refusal text** (route-level
  wall intact through the real edge).
- Explorer `health.json` `burned` column reflects the first real
  registrations (non-zero after the first reveal mines).
- **The first end-to-end registration**: an operator wallet runs
  `names register <name>` → commit → window → reveal → `names sync` sees it →
  `send --to <name>.qmb` refuses at FirstUse → `names pin` → send succeeds.
  This is the live analogue of the drill chain and the last box on [#367].

## 7. Rollback posture

Before the halt: rolling back = rolling the pre-arming image (the boundary is
in the future; nothing has changed). After the boundary finalizes: **there is
no rollback** — v3 blocks exist; a pre-#367 binary refuses the log records
that carry riders (by the additive-variant design) and the chain above the
boundary entirely. The decision point is the fid adjudication in §5 step 2,
same as emission day.

## Owed at arming, not before (parked here so nobody loses them)

- opview `burned` column (version-gated on `0x06` payloads — deferred from the
  arming-prep PR because opview reads REMOTE vintages and its supply table is
  agreement-, not detail-oriented).
- `name-service-survey-2026-08.md` lands design-side when the T2 clock starts
  (full source-verification pass; report lives on design #139 until then).
- Boundary-stamped numbers that stayed open in the brief: exact grace-window
  resolution behavior is IMPLEMENTED as "resolves, flagged" — the brief's
  leaning, ratified with PR #381; only fee-amount revisions remain boundary
  business.
