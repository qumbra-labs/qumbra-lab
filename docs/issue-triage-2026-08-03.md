# Open-issue triage, 2026-08-03 — how issues in this repo go stale, and the four ways it happens

**Snapshot pinned to `main` @ `d16ffd5`.** Every status below was read at that revision and **starts decaying the moment anything merges.** The status table is the perishable half of this document. The four failure classes in §1 are the half worth keeping.

Produced by a read-only audit (Multica QUM-70, Doc Auditor) over the 15 open issues not already under active work, plus one costing baton (QUM-71, T-build-codex) that stopped on its own stop rule. Raw output: [`issue #64`](https://github.com/qumbra-labs/qumbra-lab/issues/64) and [`issue #133`](https://github.com/qumbra-labs/qumbra-lab/issues/133).

**Nothing was closed. Nothing was modified. This document does not authorise a close** — it is the evidence a close would rest on.

---

## 1. The four ways an issue here goes stale

An issue is a claim about code at a moment. This repo moves fast enough that the claim and the code separate in more than one way, and **only one of the four is "someone fixed it."** Telling them apart is the whole content of a triage.

### 1.1 `MOVED` — the hole is still there and nothing walks into it any more

**The most dangerous class, because both halves read as true.** The cited defect is still present, verbatim, at the cited line; the *path* that reached it went somewhere else.

**`#169` is the reference case.** *"`restore_from_snapshot` drops the finalized head: written every save, read never."*

```rust
// node.rs:965-975 — the whole function, on main today
fn restore_from_snapshot(&mut self, snap: &Snapshot) {
    for cm in &snap.commitments { self.commitments.append(*cm); }
    self.commitments_ordered = snap.commitments.clone();
    for nf in &snap.nullifiers { self.nullifiers.insert(*nf); }
    self.nullifiers_ordered = snap.nullifiers.clone();
    self.roots_by_height = snap.roots_by_height.iter().copied().collect();
}
```

`snap.finalized` is still absent. **And the issue is not live**, because the function has exactly one caller — `resume_from_snapshot` — which restores finality itself 76 lines later:

```rust
// node.rs:693-703
if let Some((hash, height)) = snap.finalized {
    node.chain.restore_finalized(hash, height).map_err(NodeError::SnapshotFinality)?;
    if !records.iter().any(|rec| matches!(rec, LogRecord::Finalize(logged) if *logged == hash)) {
        return Err(NodeError::SnapshotFinalityNotLogged { hash, height });
    }
}
```

`git blame` tells the rest: **the fix landed in the caller (PR #171, `8ba0a07`) and was then relocated by `#162`'s rewind rework (PR #178, `d4f5e5f`).** Nobody moved it wrongly; a later refactor moved the code the fix lived in.

> 🔴 **An agent working from the issue text would patch a private helper that is no longer on the recovery path** — a change that passes review, passes tests, and fixes nothing.

**`MOVED` is not a close.** The right action is an amended body, because the next refactor could give the helper a second caller.

### 1.2 `PARTLY FIXED` — the title is false, the issue is not

**`#133` is the sharp case**, and it cost a dispatched baton to discover.

Title: *"Committee punishments are volatile — a restart silently restores a tombstoned equivocator to Active with a full bond."* **False on `main`.** `crates/qlab-p2p/src/punish.rs` exists; `punishments.dat` is replayed by `NodeAdapter::open` before epoch advance (PR #159, `a805488`); `prest=<restored>/<known>` is on `TELEMETRY` (PR #192, `61b599f`). Three tests execute the exact restart path — tombstone, 10 % slash, reduced bond and quorum exclusion **all survive**.

And the issue is still correctly open, because **the half that is unfixed is the half the title does not name**:

```
a_non_witness_finalizes_a_checkpoint_the_restarted_witness_refuses   (adapter.rs:3788)
  committee 7 / quorum 5, five votes {0,1,2,3,4}
  witness    excludes tombstoned signer 3 → 4 < 5 → refuses
  non-witness counts 5                    → finalizes
  restarting the witness PRESERVES the divergence rather than reconciling it
```

**A node that never witnessed the equivocation gossip never learns the punishment**, and evidence is push-once with no `InvKind`, so it cannot ask. That is `#133`'s *"there is no way to learn it again"*, and the only construction that closes it — evidence in blocks — is a **payload change riding the T1 genesis mint**, on the same preimage seam as [`#232`](https://github.com/qumbra-labs/qumbra-lab/issues/232).

> **The lesson is not "check the title."** It is that a partial fix silently re-aims the issue, and nothing updates the title when it does.

### 1.3 `FALSE AT FILING` — the premise was never true

**One confirmed instance, and it argues from the absence of an instrument that existed.**

**`#223`** states that `qumbra-opview` compares `fid` across hosts but **not** `sid`. Opview has compared `sid` **since its first commit** — `7c7c33d`, PR #119, **2026-07-30**, three days before the issue was filed:

| | |
|---|---|
| `agree.rs:70` | `SignedVerdict::VariantSplit` — *"Two nodes signed different variants at the same slot"* |
| `agree.rs:132` | `pub signed_verdict: SignedVerdict` beside the `fid` fields |
| `agree.rs:201-207` | `signed.iter().any(\|g\| g.is_split())`, computed on **every poll** |
| `render.rs:231` | `"\nsigned variant (sslot/sid): {shead}\n"` |

The two lockouts `#223` describes — slot 2064 and slot 2072, one host on a different `sid` at a shared slot — **are precisely `VariantSplit`.** Opview would have named them without a manual diff, and the issue's stated reason for their invisibility (*"a manual act nobody performs routinely"*) describes a manual act that was not necessary.

**This does not sink the issue.** Its actual ask — count the realised available-key margin per slot — has no instrument at all, and there is a real residual it could have argued instead: **telemetry carries only the *latest* `sslot`/`sid`, so a lockout is visible only if a poll lands inside its window.** That is a genuine gap; *"it does not compare `sid`"* is not.

### 1.4 `WRONG IN THE DETAIL` — the mechanism is right, a number is not

Cheapest to fix, and each one would have misdirected a fix.

**`#226`** — the mechanism is verified: `have()` is `self.voted.len()` (`round.rs:413-415`), total votes, printed beside a single-variant `need`. **The positional claim is wrong**: `variants` is not *"the third-to-last field"* — the line has 22 fields and it is **13th, i.e. 10th from the end** (`round.rs:496-530`). The issue's excerpt and `docs/incident-2026-08-02-t0-wan-7-roll.md:66` are both abridged.

> **This makes the defect worse than described, not better** — but a fix keyed on *"move it three places"* would be keyed on a line that does not exist. And field order is **test-locked** (`round.rs:1256-1267`, *"existing ROUND fields must not move or be renamed"*), so the reorder direction collides with a resident test.

**`#78`** — the body estimates `check_constraints` at 0.2 s ⇒ a 12-minute class-(2) scan. Measured by the PR #144 baton: **2.27–2.32 s ⇒ ~2.3 hours, 11× low.** Corrected in-thread; **still wrong in the body, which is what a scheduler reads.**

---

## 2. The snapshot — perishable, pinned to `d16ffd5`

**Nothing here is safe to close outright.**

| # | status | remainder |
|---|---|---|
| `#169` | **MOVED** | Hole present at `node.rs:965-975`; nothing reaches it. Amend the body, do not close. |
| `#203` | **fixed in code, unread in production** | Root cause re-attributed to `#204`/`#205`, both closed by PR #207. The one production `dfin=` sample is healthy, one host, **not a restart** — and `#203` records a restart. |
| `#106` | PARTLY FIXED | Item (1) merged (PR #153). Items (2) the 53 m 49 s wedge and (3) the `variants` correlation untouched — **both need evidence, not a builder.** All three citations moved. |
| `#133` | PARTLY FIXED | See §1.2. D1 (evidence in blocks) unbuilt. |
| `#188` | PARTLY FIXED | 1/4, 2/4, 3/4 landed (PRs #193, #202, #214). 4/4 decided and **now blocked on `#219`**, which the body does not say. |
| `#215` | PARTLY FIXED | (ii) merged (PR #216). (i) unbuilt, suspended behind `#219`. **Every citation still exact**, including `narrow.rs:170-172` "all witness". |
| `#78` | PARTLY FIXED | Findings 1 and 3 fixed; 2 and 4 open with resident SAT witnesses. **The class-(2) scan the issue was filed to obtain does not exist** — `m4gate.rs:2689` is a comment pointing at it. |
| `#107` | STILL OPEN | Fix merged (PR #132) and present. Closing needs a **WAN reading that exists nowhere in this repo**. One `grep DIAL` over the four post-roll logs settles it. |
| `#112` | STILL OPEN | The coordinator's reduced ask — two inbox-lock counters — is not on `main`. `transport.rs:118` is still a bare `Mutex`. **On time rather than late**: it belongs to the image that mints the new net. |
| `#213` | STILL OPEN | `VoteTally::on_finalized` still deletes the slot (`tally.rs:158-161`). PR #207 added the fetch and no store, exactly as filed. |
| `#220` | STILL OPEN | `ROLE_NF`/`ROLE_MERKLE` carry no domain bit. **Budget arithmetic verified**: codes 0…13 used, exactly two free. |
| `#223` | STILL OPEN | See §1.3. The margin is genuinely uncounted. |
| `#224` | STILL OPEN | No `LABEL` in `deploy/docker/Dockerfile`; `GIT_REVISION` appears nowhere. |
| `#226` | STILL OPEN | See §1.4. |
| `#235` | STILL OPEN | Not started; every row of its "already exists" table verified. |

---

## 3. What the audit deliberately did not do

Recorded because a gap named is worth more than a gap papered over.

- **Nothing was executed.** No `cargo test`, no bench, no `check_constraints`. For `#78` the finding is *which tests are resident and what they assert*, **not that they pass**.
- **No host was touched.** `#107`'s closing condition, `#203`'s restart reading, `#223`'s lockout frequency and `#133`'s live behaviour all need readings from the four T0 hosts. None were taken.
- **`qumbra-deploy` was out of scope**, which leaves half of `#224`'s citation unverifiable from here — the build recipe the issue quotes is not in this repo.
- 🔴 **`#188` 4/4 and `#215` (i) are both blocked on `#219`, and `#219` was on the skip list** — so the two largest remaining items in this pass depend on an issue nobody triaged.

---

## 4. Why this document exists at all

Because the failure it describes had already happened twice in the hour before it was written.

**A costing baton (QUM-71) was dispatched against `#133` and stopped five minutes later on its own stop rule** — the task book's premise was stale, the resurrection it was built to cost does not reproduce, and the correct answer was to report and stop rather than cost three options against a defect that is half-fixed. That baton was spent finding out what a triage would have told us for free.

**And the coordinator, checking one issue at random to justify the triage, got `#169`'s classification wrong** — calling it *fixed* when it is `MOVED`. The hole is still there. Right conclusion about the action, wrong word for the state, and the word is the part that would have driven a close.

> **The cost of not triaging is not confusion. It is dispatched work aimed at defects that are not there.**

**Suggested cadence:** re-run this pass after any wave that moves recovery, finality, telemetry or the AIR — the four areas where every citation in this round had moved.
