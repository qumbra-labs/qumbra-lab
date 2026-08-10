# The emission-rule boundary (height 18,000, ~2026-08-20) — one-page index

> [中文版](emission-boundary-index-zh.md)

**Start here on boundary day.** This page is only pointers + the go/no-go decisions; every
detail lives in the four artifacts below.

## What it is, in two sentences

At **height 18,000** the canonical emission schedule switches from the platform-dependent
`f64` form to the integer-exact one, and consensus begins enforcing
`body.coinbase == coinbase_exact(height)` — so block issuance becomes unforgeable and
bit-identical across platforms. It is a **height, not a date** (~2026-08-20 at ~48 blk/h —
track the tip, never the calendar).

## Why a halt-and-upgrade, not a hot swap

A consensus-rule change must take effect at the *same height on every node* or the net forks
(one node judges a block by the old rule, another by the new). So the armed binary **halts the
whole net at 18,000**; the resume binary carries it past. This is the halt-height upgrade
mechanism (M11, #74/#81) serving its first *real* rule change.

## The four artifacts

| you want… | read |
|---|---|
| **the WHAT/WHY** (the rule, grandfathering, the T1 gate) | `qumbra-design/protocol-spec.md` §6 amendment (EN+ZH) |
| **the HOW** (the step-by-step I execute on boundary day) | [`i299-emission-boundary-activation.md`](i299-emission-boundary-activation.md) §0–8 (EN+ZH) |
| **the record** (the −4114 defect, the census, the rulings) | lab issues [#299](https://github.com/qumbra-labs/qumbra-lab/issues/299) + [#303](https://github.com/qumbra-labs/qumbra-lab/issues/303) |
| **the live state** (fleet digests, the resume image, the 6-host note) | `qumbra-deploy/OPERATOR.md` §3 |

## The sequence, and the one decision that is not mine to force

1. Net climbs to 18,000 → the four armed hosts **halt** (finality freezes at 18,000).
2. 🔴 **GO/NO-GO — the R2 gate.** All four must read `final=18000` and the **same `fid`**.
   A `fid` split here (two hosts finalized different things at 18,000) is an **R2 STOP-POINT**:
   do NOT roll resume, preserve state, escalate to Larry. Everything else is proceed.
3. Roll the **resume** image to **all six hosts** — the four fleet nodes **and** svc0/svc1
   (the svc observer nodes predate the emission gate; OPERATOR §3 / deploy PR #115).
4. Finality resumes above 18,000 under the exact schedule once ≥⅔ of the committee is on resume.
5. Verify: `qumbra-node audit-emission --from 18001` exits 0 on all four; opview/explorer read
   epoch 15 (straddles) `AGREED`, epoch 1 `KNOWN-SCAR −4114` (no escalation).

## Current state (2026-08-10)

- **ARMED.** All four fleet hosts on `emission-armed-b2fce07` (`06baa298…4338`), halt plan
  `halts at height 18000`, v1.0. Verified healthy after the roll (uniform `fid`, finality
  advancing).
- **Resume image built + pushed**: `emission-resume-b2fce07` (`08b6c306…8385`),
  v1.1-exact-emission. Pins set (PR #336, coordinator-verified).
- **Owed at the boundary**: the halt → R2 fid check → 6-host resume roll → verify. Nothing
  before then; track the tip against 18,000.

**If the tip is within ~2 days of 18,000 and the fleet is not ready** (resume image missing,
pins wrong), re-stamp the boundary on #299 rather than racing the height — overshoot costs a
few unenforced days; undershoot halts a live net with no resume binary. Legal only until the
images are built; a new height must be `≡ 0 (mod 8)`.
