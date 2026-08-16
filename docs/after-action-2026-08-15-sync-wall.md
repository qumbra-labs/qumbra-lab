<!-- 中文对照: after-action-2026-08-15-sync-wall-zh.md · EN authoritative on technical detail -->

# After-action — the sync wall & the fleet roll (2026-08-15 → 16)

A stranger genesis-joiner could not sync this net. Six live iterations tore the wall
down — and on the far side, the light-services host and the whole consensus fleet
rolled to their first CI-built, frozen-digest-verified image.

- **frozen digest** `a54e73ce3d1c4fe9984d06b08f99b7577ed1db452b87abd712cf85ce5f3e7b5b`
- **genesis** `138e1524…addb` · **rule domain** `56447169…20b0`
- **fleet** 4 nodes across 3 continents (us-east-1 · eu-west-1 · ap-southeast-1 · ap-northeast-1)

Headline: **a from-genesis stranger joiner crossed `stip=4912` live under real RandomX and
tracked to the fleet tip** — the wall broken.

---

## 1 — Deadlock, then the wall behind it

The day opened on **#402**: a genesis-syncing joiner rejected a historical block because its
finality lagged its application, so the anchor check used the live (lagging) finalized set, not
the block's historical one. **PR #403** fixed it — a `SettledHistory` anchor gate keyed on an
O(1) main-chain height index in `ChainState`, `anchor_heights_by_root` reverse index, per-variant
tests. CI **1685/0/8**.

But live validation on a throwaway `t4g.medium` refused to cross `4912`, and **that refusal was
the real story**. Three rework rounds chased the anchor path. The fourth ran a **perf profile +
a baseline control**: the un-patched `main` reproduced the wedge value-for-value
(`tip=2000 / stip=0 / rback=234`, one `pump.dispatch` slow line). #402 was exonerated — the wall
was a pre-existing joiner-sync pathology, not the fix.

> **Written down:** before iterating a live wedge more than once, run a baseline control + a perf
> profile first. CI-green and unit-passing could not see this; only a from-genesis stranger under
> real RandomX did.

## 2 — #412: checkpoint-sync, one layer at a time

Coordinator ruling (Larry): this chain's trust root is **committee finality (quorum 15/21)**, not
per-header PoW. A joiner may trust a quorum-verified checkpoint in lieu of re-hashing every
historical header. Each live run peeled off the next bottleneck.

| Layer | Fix | PR | Effect |
|---|---|---|---|
| 1 | `submit_header` returns `Duplicate` before re-validating a stored header | #413 | RandomX in the hot path 32% → 0.74% of perf samples |
| 2 | `state_fork_point` / `missing_body_hashes` use #402's O(1) `main_chain_hash_at` instead of O(tip−stip) walks | #413 | removes the fork-point O(N²) |
| 3 | **Checkpoint-sync, buffered span** | #418 | eager-fetch a quorum checkpoint (finality → 12344), buffer the ascending header span structural-only in one accumulating session, admit the whole span **PoW-skipped** when its frontier hashes to the checkpoint block `B` |
| 4 | **Catch-up body fetch** | #418 | a joiner was *dropping the body answers it asked for* (`breq` stuck at 2–7); fixed, window sized for large slag (`breq → 95`) |

`finality.rs` / `committee.rs` quorum logic byte-unchanged. A forged/sibling header below `fin` is
not on the admitted main chain → full validation → refused. The tally-window bypass is scoped to a
**quorum-complete, explicitly-fetched** checkpoint only.

**Result, live:** `stip` climbed from a permanent stall at 16, past 4912, to the fleet tip; arm64
acceptance suite green on the merged head; `admit checkpoint=12472 headers=12472 pow=skipped` in
the log. Follow-ups filed, not buried: **#426** weak-subjectivity for dynamic rosters (T1),
**#427** catch-up throughput on modest hardware.

## 3 — Two more merges, adjudicated

- **#408 → PR #410** — a stale snapshot silently cost a full genesis replay. Now a typed rejection
  (`Undecodable` / `VersionMismatch`, plus the `.filter()`-dropped foreign-genesis case) + a
  near-tip degrade when the log's finalizations prove the snapshot tip is on the finalized main
  chain. Fails safe to full replay; `open == replay` and the lost-branch refusal are test-locked.
- **#375 → PR #416** — a halted boundary-tie loser fetches the finalized sibling and reorgs onto
  it. The cure already existed at runtime (#162 rewind + #198/#229 serving + #371 window compose),
  so the PR is the `d3_b` acceptance lock + paired operator docs, **zero consensus code**. Arms
  hard-gate #3 (#367).
- **#409** — the wallet ledger moved to a leaf crate (`qlab-ledger`) so a non-CLI shell can render
  it: `cargo build --release -p qumbra-ffi --target aarch64-apple-ios` now succeeds (the crate's
  graph no longer pulls RandomX's C++/cmake).

## 4 — The light-services roll & the first miner

With the chain-side work merged, **svc0** refreshed to main-built images, one service at a time,
each read back on the public edge.

- **cbnode → 878bc444** (deploy #146): `seed.qumbra.org/v1/coinbase → 200`, snapshot-resumed at
  13020, no genesis replay.
- **explorer-api → d47a04a0** (deploy #147): the #299 scar renders correctly again
  (`divergent=false`, `supply=COMPLETE`). Root-caused a **GHCR package ACL** as the reason the
  image had been stale since 08-13 — Actions could not publish; the `qumbra-explorer` package did
  not grant `qumbra-lab` repo Actions Write.
- **first-miner-journey** — leg 1 closed: a miner wallet read **574 mined blocks** off the live
  seed edge, reconciled to node1's quarter (574 measured vs ~576 expected); deploy #143 closed.
  Leg 2 unblocked by the **#424 proceed-loudly ruling** (a missing `/v1/coinbase` only shrinks the
  input set → fails safe; unlike a missing nullifier feed, which stays fail-closed) and merged by
  the miner lane; the FFI event-drop gap extracted as **#432** (gate before any FFI send surface).

## 5 — No more hand-built consensus images

The node image had no CI publish path — the same gap that let the explorer go stale.

- **node-image workflow → PR #431** — drift alarm + `confirm=build`-gated build+push on the paid
  arm64 runner, two variants (`emission-resume` / `armed`). **The consensus gate:** before any push
  it runs `halt-status` and asserts the **declared and recomputed-from-constants** frozen digest
  both equal `a54e73ce`, plus per-variant rule-domain / revision / halt-plan. A drifted consensus
  constant can never reach the registry. The builder corrected the task book twice: the resume
  recipe needs `FAUCET_FEATURES` too (the #397 faucet-armed trap), and the `armed` variant has a
  different rule domain by design (identifier-bound `Revision::digest`).
- **#428 → PR #429** — the explorer readback grepped `"revision":"[0-9a-f]*"` (no space after the
  colon) against buildx's spaced `json.MarshalIndent`, so a good push reported red. Replaced with a
  jq recursive-descent that reads either OCI shape (single-platform config object AND
  platform-keyed index) and **asserts** revision==`GITHUB_SHA` — `unreadable` and `mismatch` are
  now separate verdicts. Validated offline 11/11 over 7 fixtures, no paid run spent.

## 6 — The fleet roll — gated, one at a time

All four consensus nodes rolled from the hand-built `8407e1a` (f046051) to the first CI-built,
digest-verified image **`emission-resume-e0b6245` / `c7b8b334`** (deploy #148). Between every host:
fid unanimous, slag 0, mready synced. `node3` kept its `miner_rkm`; no genesis replays.

| Node | Recovery | slag | Gate | fid (final) |
|---|---|---|---|---|
| node1 | snapshot @ 13148 | 0 | pass | `482721168520` |
| node2 | snapshot @ 13151 | 0 | pass | `482721168520` |
| node3 (miner) | replay 19,802 records | 0 | pass · rkm kept | `952f707c7950` |
| node0 | snapshot, fast | 0 | pass | `952f707c7950` |

(`fid` advanced mid-roll — `482721…` → `952f707…` — as the chain finalized new checkpoints; every
gate confirmed unanimity across the four, not equality to a fixed value.)

The fleet now carries every restart/re-sync hardening merged this session (#402/#413/#418/#408/
#425/#409). An unexpected restart no longer hits the genesis-replay/RandomX wall it just tore down;
it checkpoint-syncs back in minutes. **Zero consensus-rule change** — frozen digest `a54e73ce` held
throughout, asserted by the workflow gate before push and verified independently via `halt-status`.

## Ledger

**Merged (lab):** #403 (#402) · #410 (#408) · #416 (#375) · #418 (#412) · #425 (#415) · #409 (#407)
· #429 (#428) · #431 (node-image workflow) · #430 (#424, miner lane).
**Rolled (deploy):** cbnode 878bc444 · explorer-api d47a04a0 · fleet node0-3 c7b8b334 · deploy PRs
#146 #147 #148.
**Closed:** #402 · #408 · #375 · #412 · #415 · #424.
**Open follow-ups:** #426 (weak-subjectivity T1) · #427 (catch-up throughput) · #432 (FFI
send-surface gate) · #144 (restart snapshot flush).

## The lesson

**A live wedge is guilty until a control says otherwise.** CI-green and unit-passing did not catch
the sync wall — only a from-genesis stranger under real RandomX did, and only a baseline control
told us which layer owned it. Every builder in the chain corrected the task book at least once; the
good ones stopped and escalated instead of shipping a plausible wrong fix. The frozen-digest gate
now automates the one check that must never be assumed on a consensus image.
