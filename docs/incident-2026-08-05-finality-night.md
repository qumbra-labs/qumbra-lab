# The night of 2026-08-05: a phantom split, a burned-slot outage, and the sign-hysteresis fix

> [中文版](incident-2026-08-05-finality-night-zh.md)

**Scope: WAN, the live T0 net (genesis `138e1524…addb`).** One evening produced two
incidents — one that never happened and one that did — and ended with a consensus-liveness
fix built, accepted and rolled onto all four hosts before dawn. This is the findings record;
every artifact it cites is linked at the end. Written by the session that ran the fix arc;
its own errors that night are part of the record, per the no-silent-divergence convention.

## Timeline (+08)

| time | event |
|---|---|
| 19:32–19:37 | The net crosses its **first committee epoch boundary** (block 1152) unattended: final frozen at 1120 for ~40 min pre-boundary (the known shape), then one-step finalization to 1152, epoch 0→1 |
| ~21:5x | Coordinator session runs an org-migration roll (`lai3d` → `qumbra-labs` image ref), believes node3 has forked, invokes R2, halts the roll, files **#268** |
| 22:02–22:07 | Independent analysis (this session): **the split never existed** — containers were never recreated (the roll was a host-side no-op: the pinned compose file was never rsync'd), the "fork" readings (`tip=1676`, `fid=e9de…`, `epoch=0`) exist in no log and are arithmetically impossible on a 25-hour-old chain; `fid` had also been misread as a chain identity |
| 22:14 | Larry: diagnose the no-op, re-run the roll |
| 22:18–22:27 | Re-run (rsync path, correct): four containers recreated in 9 minutes, each gate read as `slag=0` + fid — the "final advancing" condition being **unverifiable inside one 10-min cadence** |
| ~22:31 | Tip reaches checkpoint slot 1296 minutes after the last restart, mesh still re-forming: four distinct 1296-candidates, **all 21 keys sign their local variants — the slot burns 4-ways** (#223's mechanism at fleet scale) |
| 22:20–23:11 | **Finality outage, 51 minutes** (final pinned at 1288). Slots 1304 (4 variants) and 1312 (3 variants) burn too; **1320 finalizes at 2 variants** as the mesh heals — self-recovery, no intervention |
| 22:5x | This session's analysis calls the wedge *permanent* (**wrong** — it generalized from the #204 query path and read an unprinted open round as a nonexistent one; the proposer cursor walks every cadence slot), files **#269** on that premise |
| 23:15 | Self-correction posted and #269 retitled the minute the healed state was measured; deploy-side records corrected the same way (original text preserved everywhere) |
| 23:37–00:42 | Larry: fix it. **Sign-hysteresis built**: `CHECKPOINT_SIGN_HYSTERESIS_BLOCKS = 2`, slot signs at `tip ≥ S+2`; waived at slot 0 (genesis is hash-pinned) and the halt boundary (#74 requires H's checkpoint). One new test; ten test sites updated (mining-loop `+2`s, no assertion weakened). **Acceptance 1229/0/1** unfiltered, reconciled (1228 + 1) |
| 00:43–00:47 | lab PR #270 merged (`5f4123e`); **t0-wan-12** built from a clean detached tree (provenance verified step-by-step — 124 crates compiled, revision label read back), pushed, digest pinned in deploy compose (PR #75) |
| 00:48–01:24 | **Roll under the amended gate** (deploy PR #74: one NEW finalization strictly after each host's restart — written that evening from the burn, first executed here): node1→node2→node3→node0, finality **monotone 1392 → 1432 across five checkpoint slots, zero burned** |

Morning check (07:07): final=1696, fid agreed, `slag=0 schain=main` on every sample since
the roll — the drills' 24 h quiet window (restarted 01:24) accruing cleanly.

## The defect, precisely

Three facts composed into the outage:

1. `try_checkpoint` signed every cadence slot S **the moment `tip == S`** — the exact window
   in which competing S-blocks exist. #223 had named this cost per-slot; a restart-dense
   window (four recreates in 9 minutes, mesh at `peers=0→3→5`) let it burn **three
   consecutive slots**, 21/21 votes each, no variant at quorum 15.
2. Votes are immutable per slot **by design** (`FinalizerState::authorize` refuses a
   different checkpoint at a signed slot, persisted) — the never-re-sign guard held
   throughout and is not the defect; nothing was wrongly finalized at any point.
3. Recovery was **luck-shaped, not designed**: the proposer cursor does walk later slots
   (which is why "wedged forever" was wrong), but each new slot was signed at its own race
   window, so recovery waited on a round where propagation happened to be tight
   (variants 4→4→3→2 over 51 minutes).

The fix removes (1): with two blocks of burial, the slot's block is settled before any key
commits. Constant cost 150 s of finality latency. The parameter is devnet-grade and
testnet-tunable; a race deeper than 2 blocks can still split a slot — the class is
narrowed, not deleted.

## Three lessons, named

1. **A load-bearing number must arrive with its raw command and output.** #268's tables
   carried none; the readings were unanchored (the filing session had already logged two
   garbled-batch misreads that evening) and the R2 STOP was called on numbers that a
   one-line arithmetic check — tip vs. chain age × cadence — would have refuted. This is the
   07-31 "`ROUND lines: 0`" failure family in a new costume.
2. **An analysis of "impossible" needs the production caller, not a plausible one.** The
   "wedged forever" claim generalized `next_checkpoint_height` from the #204 *query* path
   and treated an unprinted (open) round as a nonexistent one. The correction landed within
   minutes of contrary evidence — but the wrong claim drove an evening of recovery-option
   planning. Symmetry worth keeping: **two sessions built confident wrong conclusions the
   same night** — one from phantom evidence, one from incomplete code reading — and both
   were caught by the same discipline: dated correction, original preserved.
3. **A gate must be verifiable on the timescale it gates.** "final= is advancing" cannot be
   read inside one 10-minute cadence, so under time pressure it degrades to the two gates
   that *can* be read — which is how four restarts landed in 9 minutes. The amended gate
   (one NEW finalization strictly after each restart) is checkable by construction, and its
   first execution crossed five checkpoint slots without a scratch.

## What this cost and what it bought

~51 minutes of finality outage (self-healed), ~4 session-hours of night work, five
fleet-wide restarts in twelve hours. Bought: the first roll this net has ever completed
without wounding finality, a liveness fix for the sharpest defect class the T0 net has
produced, an operational gate that makes the defect's trigger unreachable in routine ops,
and — unplanned — a live full-arc observation of committee stall → recovery, the exact
subject of drill D3.

## Artifacts

- lab [#268](https://github.com/qumbra-labs/qumbra-lab/issues/268) (the phantom; analysis in-thread) ·
  [#269](https://github.com/qumbra-labs/qumbra-lab/issues/269) (the defect; self-correction in-thread) ·
  [PR #270](https://github.com/qumbra-labs/qumbra-lab/pull/270) (the fix; closed #269)
- deploy [PR #72](https://github.com/qumbra-labs/qumbra-deploy/pull/72) (incident record) ·
  [#73](https://github.com/qumbra-labs/qumbra-deploy/pull/73) (dated correction) ·
  [#74](https://github.com/qumbra-labs/qumbra-deploy/pull/74) (gate amendment) ·
  [#75](https://github.com/qumbra-labs/qumbra-deploy/pull/75) (t0-wan-12 pin) ·
  [#76](https://github.com/qumbra-labs/qumbra-deploy/pull/76) (roll record)
- `qumbra-deploy/tasks/roll-org-ref-and-finality-wedge-2026-08-05.md` ·
  `tasks/roll-t0-wan-12-2026-08-06.md` · `qumbra-ops/image-build-t0-wan-12.log` ·
  sampler `qumbra-ops/t0-138e1524.log` (iters ~256–290 hold the whole arc)
