# Builder prompt — issue #115: genesis binds its own body, and the free moment is now

## Your task book

https://github.com/qumbra-labs/qumbra-lab/issues/115

Read the issue body, then the coordinator's task-book comment (the most recent one). The issue carries the *what* and the *why it was deliberately not done in `PR #113`*; the task book carries what has changed since it was filed.

## Why this is being dispatched today

The issue was filed to claim a free moment rather than to be urgent: *"Do this at the next real genesis mint — the identity is changing anyway at that moment, so F1 costs nothing extra. At any other time it is a gratuitous network-identity change."*

**That moment has arrived.** `qumbra-deploy/OPERATOR.md` §4's gate is now:

```
issue #130 (a) ✅ PR #142  →  issue #106 (PR #153, in acceptance)  →  mint  →  the four drills
                                                                      ^ you
```

You are the **only thing on the mint's critical path with nobody on it.**

## The issue's own sequence diagram is stale — ignore that one line

It says `#107 resolves → #106 fixed → new genesis`. **`issue #107` was re-sequenced out on 2026-07-30** (four hypotheses dead, no local reproduction, and bisecting on the hosts is impossible because `issue #101` moved the genesis identity). It is answered *by* the new net. `OPERATOR.md` §4 is authoritative.

## 🔴 The trap, and it is the opposite of the last baton's

**Golden vectors WILL break, and that is correct.** `body.rs:92-97` already records the rule from `issue #101`'s change:

> *"a later change to this preimage **MUST** break that test."*

**A PR here whose golden vectors still pass has not done the work.** Update them in the same commit and state the new genesis hash in the PR body.

Contrast `PR #149`, merged this morning: it tightened a decoder and its golden test had to pass **unmodified**, because it changed what is *accepted* rather than what is *emitted*. **Knowing which of the two kinds of change you are making is the whole skill here** — and getting it backwards looks like success in both directions.

## Three more things you cannot know from the issue

1. **Do not touch `qumbra-deploy`'s pinned genesis hash.** The pin moves in the same act as the mint, not before, or `OPERATOR.md` names a genesis no host is running. Report the new hash; the coordinator moves the pin.
2. **`Node::open` checks `snap.genesis_hash == chain.genesis_hash()` (`node.rs:204`) and falls through to a full replay rather than refusing.** Anything you write that assumes a mismatched snapshot gets rejected is wrong.
3. **`genesis.rs` / `params_audit.rs` bake FROZEN constants into the genesis file.** You are changing how the genesis *header* is formed, not any frozen parameter. **Editing a FROZEN constant is a STOP-POINT** — report and wait.

## The test that proves it happened

> *A test that a genesis with a mismatched body is rejected — **the exemption's whole point was that this could not be expressed.***

Delete the height-0 exemption; do not branch around it. If the exemption survives as a special case, the property above is still inexpressible and the baton has not landed.

## Working rules

- **worktree + PR, never direct to `main`**: `git worktree add ../qumbra-lab-i115 -b claude/i115`. Say the path in your first reply.
- **Full unfiltered `cargo test --release --workspace -- --test-threads=1`, raw total.** `main` was **938 passed / 0 failed** at `PR #144`, but `PR #153` may land before you — reconcile against whatever `main` is when you branch and **say which commit you branched from**. If it does not reconcile, say that before explaining anything else.
- Check **[`issue #64`](https://github.com/qumbra-labs/qumbra-lab/issues/64)**'s latest comment for the rig queue and post start/finish lines. QUM-29 is also queued; one release suite at a time.
- **Blocked on a judgement call that is not a STOP-POINT: take the smaller action, mark it separable, and say in the PR that you asked and proceeded. Do not wait for the coordinator.**

Closes `issue #115`.
