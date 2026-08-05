# The rig — what it is, why it is serial, and what a green here actually proves

> [中文版](the-rig-zh.md)
>
> Written 2026-08-03 at Larry's request, after the question "where does the full suite run — CI or local?" The one-sentence answer: **local, on this machine, under a mutex** — and every clause of that sentence was paid for. Sources: `scripts/rig` (77 lines, read in full), `CLAUDE.md` §5 (bench discipline), issue #64's collision record, the 2026-08-01 same-tree incident, and one fresh instance from today.

## 1. What "the rig" is

Three things wearing one name:

1. **The machine** — Larry's MacBook Pro (Apple M5 Max, 18 cores, 36 GiB, macOS). Every acceptance suite, every proof-size reproduction, every RSS gate measurement in this repo's history ran here. Bench numbers carry this machine's identity (bench discipline #2) because they are meaningless without it.
2. **The mutex** — `scripts/rig`, a 77-line bash wrapper around an atomic `mkdir`.
3. **The discipline** — one heavy job at a time, full workspace, serial, and the lock binds *everyone*, coordinator included.

## 2. The mutex, mechanically (from the source, not from memory)

```sh
scripts/rig run -- cargo test --release --workspace -- --test-threads=1
scripts/rig ps          # running + queued + last 5 completions (rc, log path)
scripts/rig log -f      # follow the current holder's log
scripts/rig status      # holder one-liner (stable output, for scripts)
scripts/rig release     # manual break — only if a trap failed to fire
```

*(2026-08-05: every `run` now auto-tees to `~/develop/qumbra/logs/rig-<stamp>-<pid>.log`,
waiters are visible in `ps` instead of queueing silently, and completions append to
`logs/rig-manifest.tsv` — start, end, owner, rc, log, cmd.)*

- **The lock is a directory**: `~/.qumbra-rig.lock` (override: `QUMBRA_RIG_LOCK`). Acquisition is `mkdir`, which is **atomic** on POSIX — two contenders cannot both succeed. Inside it: `owner`, `pid`, `started`, `cmd` — so `status` can answer *who/since when/what* without guessing.
- **Waiting is polling**: a contender retries every 15 s, logging a "waiting for <owner>" line at first wait and every 5 minutes. This is why a queued suite can legitimately sit 50+ minutes before its first line of output — observed 2026-08-03: a wrapper acquired at 16:46 started its cargo at 17:38.
- **Owner identity**: `QUMBRA_RIG_OWNER`, else `MULTICA_ISSUE_ID` (so a Multica baton's lock reads as its issue key), else `user@host`.
- **Stale-holder reaping**: a holder whose pid no longer exists (`kill -0` fails) is reaped automatically by the next contender or `status` call. Without this, one crashed baton wedges the rig until a human notices — "which is worse than the race we fixed" (the script's own comment).
- **Release is a trap** on `EXIT INT TERM` — Ctrl-C and kills release the lock. The wrapper echoes `rig: command exited N` on completion; **that line is the exit-status authority** for anything piped through `tee` (zsh's `$pipestatus` vs bash's `$PIPESTATUS` has already eaten one report's exit capture).

## 3. Why a lock and not a convention

The convention it replaced was *"check `ps`, then post a START line on issue #64"*. That is **check-then-act**, and the gap between the check and the act is real:

- issue #64 records **two collisions** from exactly that gap — two batons read "machine free" and started 56 seconds apart; separately, the coordinator collided with a baton six minutes into its run.
- On **2026-08-02 a measurement read 2.1× its true value** because a suite started underneath it. It was caught only because that baton knew what a contaminated run looks like.
- The thread's own remedy ("re-check `ps` immediately before `cargo test`") narrows the window; `mkdir` closes it.

**Issue #64 survives as a log, not a mechanism** — post there for the record of what ran and what it cost, never for permission.

## 4. Why serial is a hard constraint, not a preference

- The release suite **peaks 16–30 GB on a 36 GiB machine**. `qumbra-node` carries **three real M3 prove tests**; two suites at once is not slow, it is dead (or worse — silently wrong numbers, see §6).
- `--test-threads=1` is required *within* a suite for the same reason. The long poles are the prove tests: in the 2026-08-03 run, single tests of **973 s** and **238 s** sat inside a ~55-minute total.
- Wall-clock for the full bar on this machine: **~20–55 min** depending on tree size and thermal state. Budget for it; never trim it (see §5).

## 5. What runs under the lock, and what a green proves

The acceptance bar (CLAUDE.md §5, binding):

```sh
scripts/rig run -- cargo test --release --workspace -- --test-threads=1
```

- **Full workspace, unfiltered.** Mode-scoped filters and crate-scoped runs are both banned, each ban paid for separately: a filtered run let a stale width pin drift for three sessions (PR #23 era); PR #166 reported two honest crate-scoped greens while the workspace suite failed **in a crate neither run touched**.
- **Reconcile the arithmetic out loud**: total = `main` baseline + your new tests − your deleted ones. Verify the negatives — `FAILED` (case-sensitive), `panicked at`, `^error` all zero. Exit 0 from a launcher is not exit 0 from the suite.
- **What is deterministic and what is not**: proof *sizes* are byte-deterministic (assert them; 5/5 identical runs is the reporting convention). Prove *time* carries grind-PoW jitter (±30–60 % is normal) — judge against the envelope, never flag a single delta.
- **A stated exception is allowed; a quiet skip is not.** A docs-or-shell-only diff structurally cannot fail the suite; write the exception and its differential evidence into the acceptance comment (precedent: PR #170).

## 6. Contamination and interruption — the failure modes actually observed

- **Contamination tell**: `sys` time inflated several-fold with instructions-retired nearly flat ⇒ something else was running ⇒ **discard the number, do not caveat it**.
  *(Refined 2026-08-04, from the mint-combo baton's b4 measurement: inflated `sys` with instructions-retired **risen** is a different animal — that is this machine's own memory compressor doing real work (a ≥33 GB-class footprint forces it), the number is genuine and the machine is merely at its limit; the discriminator is instructions, not sys.)*
- **Lid-close kills runs** (2026-08-03, twice-verified): closing the MacBook killed a suite mid-test — log truncated mid-line, no process left, lock correctly reaped as stale afterwards. A partial suite result is worthless; the rule is **restart from scratch, overwrite the log**.
- **Background watchers die more often than the watched** — the WAN sampler died three times in four days while all four nodes held `restarts=0`. Same lesson at rig scale: never assume a long-lived background process survived a period nobody was watching. Check `rig status` / the log's tail, not your memory of having started it.

## 7. Where CI stands relative to the rig

CI exists and is **not the acceptance authority**. The 2026-08-01 incident is the reason, in one line: **CI was green on the pre-merge head — a tree that did not contain the conflict resolution that broke the merged tree.** A green on a different tree is not evidence about the tree being merged.

CI's legitimate role, earned the same day: after resolving a conflict or merging `main`, **push the merged tree to the PR branch** so CI re-runs on the same tree the rig sees — then it is a free second line running on someone else's hardware, in parallel. Five same-tree comparisons that day agreed exactly (1030 → 1051 across five trees). Runner cost and SKU decisions live in `docs/ci-runner-cost-decision.md` (§10 carries the stop-usage blast-radius analysis); that doc, not this one, is authoritative on CI economics.

## 8. Etiquette summary (the whole protocol in five lines)

1. Every heavy command goes through `scripts/rig run --` — including the coordinator's.
2. If you must run heavy work outside the wrapper, wrap it: `scripts/rig run -- bash -c '…'`.
3. Queueing is normal; a 50-minute wait for the lock is the system working, not stuck.
4. `rig status` is the liveness check; issue #64 is the ledger; neither is the other.
5. If a number looks wrong, suspect the machine before the code: contamination, thermals, battery, or a sleep event — and rerun rather than reason.
