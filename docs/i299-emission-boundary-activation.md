# Emission-rule boundary — activation procedure (lab #299 + #303)

**繁體中文版本**: [`i299-emission-boundary-activation-zh.md`](i299-emission-boundary-activation-zh.md)
(EN is authoritative on technical detail.)

Audience: **T-ops**, plus the coordinator who accepts the roll. This is the live half
of the emission-rule baton — the half a builder session cannot do, because it needs
host access and a Linux/glibc machine.

> **Orienting on boundary day? Start at [`emission-boundary-index.md`](emission-boundary-index.md)** —
> a one-page index of what the boundary is, the go/no-go (R2) decision, and where every
> artifact lives. This file is the step-by-step it points at.

It is written here rather than in `qumbra-deploy/OPERATOR.md` because
`qumbra-deploy` is a stop point for this baton. Fold it into `OPERATOR.md` §4 when
convenient; nothing below depends on where it lives.

---

## 0. What is changing, in two sentences

`RULE_BOUNDARY_HEIGHT = 18_000` is the **last block** mined and validated under the
`binary64` emission schedule. From 18,001 the canonical schedule is the exact-decimal
one (`qlab_devnet::emission_exact`) and `body.coinbase == coinbase_exact(height)` is a
**validity rule** — a block that commits the wrong amount is rejected, and its sender
is scored as a peer fault.

Everything at or below 18,000 is grandfathered **as recorded**: the epoch-1 −4114
block stays, every glibc-vs-exact ±1 stays, and nothing recomputes them.

It is a **height, not a date.** At the cadence measured when it was stamped
(~47.7 blocks/h) it arrives around 2026-08-20 ±½ day of PoW variance. Track the tip,
never the calendar.

## 1. Preconditions

| Check | How |
|---|---|
| The lab PR is merged and `main` carries `RULE_BOUNDARY_HEIGHT` | `grep -r RULE_BOUNDARY_HEIGHT crates/qlab-devnet/src/emission_exact.rs` |
| The tip is **well below** 18,000 — at least ~2 days of margin | `curl -s https://explorer.qumbra.org/v1/health.json` |
| All four hosts are reachable and at the same `fid` | `OPERATOR.md` §3 cross-host check |
| The resume image is **built and pushed** before the armed image is rolled | see §3 |

🔴 **If the tip is within ~2 days of 18,000 and the fleet is not ready, ask for a
fresh stamp on lab #299 instead of racing the height.** Overshooting costs a few more
days of an unenforced schedule; undershooting halts finality on a live net.
Re-stamping is legal and cheap only until the images are built — the constant compiles
in — and any new height must be **≡ 0 (mod 8)** (`release.rs` refuses an off-grid halt
height at startup, and `emission_exact.rs` refuses it at compile time).

## 2. Step 0 — the pins (do this first, on a glibc host)

The historical schedule is platform-dependent (#303). Three constants pin what it
produced so that nothing above the boundary ever evaluates a float, and so a
non-glibc node computes the same accounting:

```sh
# on any Linux/glibc host, from the release image
qumbra-node emission-pins
```

It prints three pasteable blocks and the host it ran on. Paste them into:

- `crates/qlab-node/src/emission.rs` — `PINNED_S_ATOMIC_AT_BOUNDARY`,
  `PINNED_COMMITTEE_ACCRUAL_AT_BOUNDARY`
- `crates/qlab-node/src/supply.rs` — `PINNED_EPOCH_EXPECTED` (15 rows, epochs 0..=14)

The command is **pure** — no data dir, no network, no chain — so anyone can rerun it
and compare. Verify the header line names `linux`; a pin produced on macOS is the one
mistake this step can make, and it would be invisible until a stranger's node
disagreed with the fleet.

Unpinned, the fallback is the historical walk, which is what the glibc fleet already
computes — so **skipping this step changes nothing on the current four hosts and
leaves the T1 hardening undone.** It is not optional for T1; it is optional for
today.

While the pins are unset, epoch 1's annotated `KNOWN-SCAR` verdict is also only
platform-stable on glibc (a non-glibc attester may compute −4113/−4115 and show
`DIVERGENT`). Pinning epoch 1 fixes that too.

## 3. Build both images before rolling either

Two binaries come out of the same source:

```sh
# the ARMED announcement binary — this is the DEFAULT build
cargo build --release -p qumbra-node
#   banner: "halt plan: halts at 18000"

# the RESUME binary — the one that goes past the boundary
cargo build --release -p qumbra-node --features rule-boundary-resume
#   banner: "resumes past: height 18000", revision v1.1-exact-emission
```

🔴 **Build and push the resume image first.** The armed image halts the net at
18,000; if the resume image does not exist at that moment, finality is stopped until
it does.

## 4. Roll the armed image (before height 18,000)

One host at a time, per `OPERATOR.md`. On each host, read the banner back:

```
  release:      qumbra-node v1.0 (halts at the emission-rule boundary, lab #299/#303)
  halt plan:    halts at 18000
  revision:     v1.0
```

If a host does not print `halts at 18000`, it did not get the new image — fix that
before moving on. A mixed population is tolerated by design (§4 of
`committee-and-governance`), but a host still on the old image will keep mining above
18,000 on a branch the upgraded population refuses.

## 5. Let the net halt at 18,000, then check the boundary is finalized

18,000 is a checkpoint-cadence multiple (8 × 2,250) precisely so the boundary is a
**finalized** boundary. Before touching anything:

- every host reports `final=18000` and the **same `fid`** (`OPERATOR.md` §3);
- a `fid` split here is a 🔴 STOP, not a finding: do not roll the resume image, and
  report on lab #299.

The armed binary can be restarted freely at this point — it cannot go past the
boundary, so restarting it to inspect a halted node is explicitly allowed and
test-locked.

## 6. Roll the resume image

One host at a time. Each host rewrites its halt marker to record
`v1.1-exact-emission` as the revision in force and the boundary as **passed**. After
that:

- a **pre-rule** binary (any image built before this change) is refused with
  `UndeclaredResume` — that refusal is the point, and it is what stops an
  un-upgraded node validating post-boundary blocks under the platform-dependent
  schedule;
- a future routine release carrying the same revision starts freely and reads its PoW
  rule domain off the marker (#81).

Finality resumes above 18,000 once ≥⅔ of the committee keys are on the resume image.

## 7. Verify the rule actually bound

```sh
qumbra-node audit-emission --data-dir /opt/qumbra/data --from 18001
#   exit 0 = every post-boundary block committed coinbase_exact(height)
```

Run it on all four hosts. Then, on the operator view:

- epoch 15 straddles the boundary (`17_280..=18_431`) and its expected side is
  piecewise: the recorded pre-boundary prefix plus the exact walk above. It should
  read `AGREED`, and **a ±1 of grandfathered history inside 17,280..=18,000 cannot
  make it read otherwise** — that is deliberate, and it means a per-block defect in
  that prefix must be found with `audit-emission`, not with the epoch row;
- epoch 1 reads `KNOWN-SCAR −4114` with its #299 citation and does **not** raise the
  divergence exit. Any other non-zero total anywhere still does.

## 8. What "done" looks like

- all four hosts on the resume image, same `fid`, `final` advancing above 18,000;
- `audit-emission --from 18001` exit 0 on all four;
- the pins pasted and merged (or an explicit decision recorded on #299 to defer them
  past T1 — see §2 for what that leaves undone);
- the T1 gate discharged: **the boundary is passed before public mining opens.**
