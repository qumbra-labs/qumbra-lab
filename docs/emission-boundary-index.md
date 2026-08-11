# The emission-rule boundary (height 8,640, ~2026-08-12) — one-page index

> [中文版](emission-boundary-index-zh.md)

> 🔴 **Re-stamped 2026-08-11: the boundary moves from 18,000 to 8,640.** See
> [Larry's ruling on issue #299](https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483)
> and the re-stamp note atop [`i299-emission-boundary-activation.md`](i299-emission-boundary-activation.md).
> Everything below is written for **8,640**; the "Current state" section reflects the
> prior 18,000-armed fleet, which is superseded and must be rebuilt and re-rolled.

**Start here on boundary day.** This page is only pointers + the go/no-go decisions; every
detail lives in the four artifacts below.

## What it is, in two sentences

At **height 8,640** the canonical emission schedule switches from the platform-dependent
`f64` form to the integer-exact one, and consensus begins enforcing
`body.coinbase == coinbase_exact(height)` — so block issuance becomes unforgeable and
bit-identical across platforms. It is a **height, not a date** (~2026-08-12 at ~48 blk/h —
track the tip, never the calendar).

## Why a halt-and-upgrade, not a hot swap

A consensus-rule change must take effect at the *same height on every node* or the net forks
(one node judges a block by the old rule, another by the new). So the armed binary **halts the
whole net at 8,640**; the resume binary carries it past. This is the halt-height upgrade
mechanism (M11, #74/#81) serving its first *real* rule change.

## The four artifacts

| you want… | read |
|---|---|
| **the WHAT/WHY** (the rule, grandfathering, the T1 gate) | `qumbra-design/protocol-spec.md` §6 amendment (EN+ZH) |
| **the HOW** (the step-by-step I execute on boundary day) | [`i299-emission-boundary-activation.md`](i299-emission-boundary-activation.md) §0–8 (EN+ZH) |
| **the record** (the −4114 defect, the census, the rulings) | lab issues [#299](https://github.com/qumbra-labs/qumbra-lab/issues/299) + [#303](https://github.com/qumbra-labs/qumbra-lab/issues/303) |
| **the live state** (fleet digests, the resume image, the 6-host note) | `qumbra-deploy/OPERATOR.md` §3 |

## The sequence, and the one decision that is not mine to force

1. Net climbs to 8,640 → the four armed hosts **halt** (finality freezes at 8,640).
2. 🔴 **GO/NO-GO — the R2 gate.** All four must read `final=8640` and the **same `fid`**.
   A `fid` split here (two hosts finalized different things at 8,640) is an **R2 STOP-POINT**:
   do NOT roll resume, preserve state, escalate to Larry. Everything else is proceed.
3. Roll the **resume** image to **all six hosts** — the four fleet nodes **and** svc0/svc1
   (the svc observer nodes predate the emission gate; OPERATOR §3 / deploy PR #115).
4. Finality resumes above 8,640 under the exact schedule once ≥⅔ of the committee is on resume.
5. Verify: `qumbra-node audit-emission --from 8641` exits 0 on all four; opview/explorer read
   epoch 7 (straddles) `AGREED`, epoch 1 `KNOWN-SCAR −4114` (no escalation).

## Current state (2026-08-11, re-stamp)

- **SUPERSEDED: the prior 18,000-armed fleet.** As of 2026-08-10, all four fleet hosts were on
  `emission-armed-b2fce07` (`06baa298…4338`), halt plan `halts at height 18000`, v1.0, with the
  resume image built + pushed (`emission-resume-b2fce07` `08b6c306…8385`, pins PR #336). That
  arming is now stale: per the re-stamp ruling, both images must be **rebuilt at 8,640** (new
  pins re-derived from the edited tree, this doc's R3 PR) and the four hosts re-rolled — a third
  production roll, its own #300/#287-class exposure accepted by the ruling.
- **Owed at the boundary**: rebuild both images at 8,640 → roll armed to all four → the halt →
  R2 fid check → 6-host resume roll → verify. Track the tip against **8,640**.
- **The abort line, restated for R3**: a partial fleet must never meet the boundary. If all four
  hosts do not read `ARMED — halts at 8640` by height **~8,300** (~7 h of lead at re-stamp
  pace), resolve the mixed state immediately — complete the roll or revert to the 18,000-armed
  image — and bring the boundary question back to #299 for a fresh stamp.

**If the tip is within margin of 8,640 and the fleet is not ready** (resume image missing,
pins wrong), re-stamp the boundary on #299 rather than racing the height — overshoot costs a
few unenforced days; undershoot halts a live net with no resume binary. Legal only until the
images are built; a new height must be `≡ 0 (mod 8)`.
