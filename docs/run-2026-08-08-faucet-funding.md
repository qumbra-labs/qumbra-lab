# 2026-08-08 — funding the faucet, and what the fleet was actually doing

*[中文](run-2026-08-08-faucet-funding-zh.md) · EN is authoritative on technical detail.*

A session record kept for review. It covers one deliverable (the T1 faucet gets a funding
source) and one thing found on the way that is larger than the deliverable.

**Scope note.** The operational half — what was run on which host, in what order — is in
`qumbra-deploy/OPERATOR.md` §9.5.2 and is not repeated here. What is here is the reasoning, the
finding, and the errors, because those are what a review is for.

---

## 1. What this was supposed to be

The T1 faucet holds a spending key and needs coins. Two ways to get them:

- **(a)** a fleet host sets `miner_rkm` to the faucet's receive key, and pays it;
- **(b)** the faucet host runs a miner of its own.

Larry asked which was correct, explicitly ruling out shortcuts. **(a)**, on three grounds, none
of which was convenience:

1. **(b) changes the net.** It adds a fifth miner to the four-host net the §4 drills were just
   run against, so every drill result becomes a result about a different topology.
2. **(b) puts the prover on the hot-key host.** One grant proof peaked at **11.89 GB** measured
   (lab PR #128), and svc1's 16 GB sizing exists for exactly that. A miner beside it contends
   for the memory the dispense path needs, and the failure mode is the worst shape available:
   the faucet runs, serves the form, accepts a request, and fails at dispense.
3. **§9.2's rule generalises.** "The hot key never shares a host with anything it does not
   need" — and a faucet *is* a wallet holding a hot key.

That much was settled quickly. Then executing it required restarting a consensus host, and
that turned out to be the interesting part.

---

## 2. The finding: the net has been running with no signing margin

### 2.1 What was measured

Sampled closed `ROUND` lines on all four fleet hosts. Every round, on every host:

| absent host | `have` | margin against `need=15` |
|---|---|---|
| any 5-key host (node1/node2/node3) | 16 | **1** |
| **node0 (6 keys)** | **15** | **0** |

Not one sampled round reached 17. **Exactly one host's key range is missing from every round**,
and which host it is rotates. `seen == have` and `variants=1` throughout, so none of it is vote
splitting. This is the steady state — nothing was mid-roll, all four hosts healthy.

### 2.2 Why

`crates/qumbra-node/src/run.rs:2202-2206`, and this is the **only** non-test call site of
`try_checkpoint`:

```rust
if self.mining && self.last_mine.elapsed() >= self.mine_interval {
    if self.try_mine() {
        self.try_checkpoint();
    }
}
```

`note_local_proposal` is called only inside `try_checkpoint`. A host that does not win a block
in the window **never proposes, never signs, and contributes zero votes** — its keys are absent
everywhere including its own tally. Observed as recurring `local=0` rounds on every host, with
that host's own key range absent.

This is lab #106's third recorded item. What the record understated: `CLAUDE.md` and PR #153
scope the coupling to *"a `mining = false` node holding keys never proposes"*. On a 4-miner net
it degrades **every mining node, continuously**.

### 2.3 There are two mechanisms and they must not be collapsed

- **(A) structural** — didn't mine ⇒ no vote at all.
- **(B) timing** — voted, but the votes miss the close at peers. Slot 4040: node0 reports
  `local=6 seen=16`, node1 and node3 close the same slot without those six (`absent=0..5`).
  `quorum_ms` measured **155–269 s** per round (#107 territory).

#106's body reads one of these as *"node3's keys — slow, not down"*. That is right for (B) and
wrong for (A), and (A) is the one that is structural and always on.

### 2.4 The operational consequence

**Any single-host restart drops the net below quorum for most rounds.** Stopping a 5-key host
leaves 16, minus whichever host is silent that round ⇒ 10 or 11 against 15. Stopping node0
leaves 15, and the same argument gives 9 or 10. So a restart **stalls finality for its
duration** rather than blipping — which is why node3 was chosen (5 keys, and already the least
consistent signer in a 12-round sample) and node0 was not.

🟡 It also means the §4 2+2 partition drill's stated mechanism is over-attributed: its
conclusion (both sides stall) is right, but "11 and 10 keys per side, both below quorum" implies
the *partition* causes it. Losing one host does it too.

**Safety was intact throughout** — `cpid` identical on all four hosts at the same slot,
`variants=1`, `seen==have`. #84's `cpid` on `ROUND` answered that in one command, which is
exactly what it was built for.

Filed to [#106](https://github.com/qumbra-labs/qumbra-lab/issues/106#issuecomment-5223333302).

---

## 3. What was delivered

svc1 brought up from `stopped` to serving in one pass; `qumbra-faucet keygen` run **on svc1** so
the seed never moved; node3's config validated with `qumbra-node check` **against a candidate
file, without restarting**, then swapped and restarted.

The restart was clean — `RECOVERY restored snapshot at height 4073, replayed 0 records, resumed
at tip 4073`. No resync-from-genesis, **no repeat of #106's fork**, which is #104's persistence
and #106 item (1)'s gate both working on a real roll. A new finalization landed ~2.5 min later,
and all four hosts converged on `fid=f411cd30c93e` at `final=4072` (node1 lagged one checkpoint
for ~40 s — lag, not a split: a split is a *different* `fid` at the *same* height).

Two defects found:

- 🔴 **compose entrypoint** — the faucet container CrashLooped on first `up -d`. Third instance
  of one shape; `docker-compose.svc-light.yml` already carried a written note about the
  identical failure. The file had never been executed. Fixed in deploy PR #92. The obvious
  "fix" (`command: ["faucet"]`) is worse than the crash — that branch is the localhost harness
  and writes `mining = true` onto the hot-key host.
- 🟡 **`deploy.sh` does not emit `miner_rkm`** — added by hand against the file's own
  "do not hand-edit" banner, so a re-deploy against node3 silently un-funds the faucet. Not
  fixed; recorded in OPERATOR §9.6.

---

## 4. My own errors, and what caught each

The most useful part of this record. Three, all published or nearly so before being caught.

### 4.1 A regex that read index lists as counts

`voted=` and `absent=` in a `ROUND` line are **index lists**. `voted=[0-9]+` matches `voted=0`
out of `voted=0,1,…,15` and reads as *"this node cast zero votes"* — the exact opposite of the
truth. A `paste`-based multi-field extraction then misaligned across rounds whenever a line
lacked a field.

**Result:** a clean, coherent, entirely wrong table showing all four hosts at `voted=0`, from
which I nearly concluded which host to restart.

**What caught it:** arithmetic. `absent=16` alongside `have=16` cannot both describe one round
of a 21-member roster. The numbers refused to add up before anyone checked them against
reality.

**The rule:** read whole raw lines before deriving anything from a field extraction. The
per-node contribution field is `local=`.

### 4.2 A host address taken from context instead of the source of truth

I ssh'd node2 at `3.72.196.15` — not node2, not any host in this fleet, a stale address carried
in from earlier context. It timed out. **I published that as "node2's operator channel is
down"** on #106 before checking the address.

**What should have caught it, and did not:** `aws ec2 describe-instances` returned empty for
that IP in **all five regions I checked**. That is disconfirming evidence for "the host has a
problem" and confirming evidence for "the address is wrong", and I read past it.

**What did catch it:** reading `terraform output hosts_file` for an unrelated reason.

**The rule:** fleet addresses come from `terraform output hosts_file`. Withdrawn publicly in
[a follow-up comment](https://github.com/qumbra-labs/qumbra-lab/issues/106#issuecomment-5223384517).

### 4.3 `gh` resolving the wrong repository

`gh issue comment 106` resolves the repo from **cwd**, and an earlier `cd` into
`qumbra-deploy/terraform` was still in effect. The correction to #106 was addressed at
`qumbra-deploy`. It 404'd because that repo has no #106 — **it could just as easily have landed
on an unrelated issue.**

**The rule:** always pass `-R qumbra-labs/qumbra-lab`.

### 4.4 The pattern across all three

Each was a **plausible reading that survived because nothing forced it to meet a second
source.** The finding in §2 is the same shape inverted: it survived on a live net for weeks
because `have=16 need=15` looks like a healthy round, and only comparing four hosts' views of
the *same slot* made the structure visible.

---

## 5. What ordering cost, and what it saved

Larry approved restarting node3 before the faucet's rkm existed. Executing that approval
immediately would have meant a stall, no config change, and a second stall later — because
`miner_rkm` can only be derived from a seed that did not yet exist.

Checking the prerequisite first turned two stalls into one. **A granted approval is not a
reason to skip asking what the action depends on.**

---

## 6. Open

| item | owner |
|---|---|
| `deploy.sh` does not emit `miner_rkm` — a re-deploy un-funds the faucet | lab |
| 🔴 CF rate limit + Managed Challenge — **the open faucet's entire abuse control**, and it does not exist. Must precede the `faucet.` A record | Larry |
| `faucet.qumbra.org` proxied A record → svc1's EIP | Larry [manual] |
| 144 blocks (~3 h) until the first coinbase matures and the faucet can serve | time |
| Whether svc1 stays up (~$95/mo) or returns to start/stop | Larry |
| #106 items (2) the wedge and (3) the `variants` correlation | still open |
