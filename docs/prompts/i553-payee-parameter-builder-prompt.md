# Task book — lab #553: the mine-RPC template must **accept** a payee list, not merely report one

**Issue**: [lab #553](https://github.com/qumbra-labs/qumbra-lab/issues/553)
**Ruled by Larry 2026-08-21 22:31 +08**: *"我们选择正确的,不走捷径"* — build the real payout
path. The two workarounds that were on the table (a random per-job lottery, and a deterministic
owed-balance scheduler at cap 1) are **both declined**. Read §1 for why, because it is the reason
this baton exists and the reason it is shaped the way it is.

**Scope of THIS baton**: the payee parameter, end to end, list-shaped. **The cap stays at 1.**
Raising `COINBASE_PAYEE_CAP_V5` is a separate halt-boundary rule change and a separate baton; this
one must land so that that one is a constant and a height and nothing else.

---

## 1. Why the shortcuts were declined — the arithmetic that decided it

`COINBASE_PAYEE_CAP_V5 = 1`, and the payee is bound into the header the miner grinds against, so
**the payee must be chosen before the work is issued.** With one payee per block, a pool can only
pay one miner per block. The obvious workaround is a lottery: draw the payee ∝ PPLNS share, and
whoever's job finds a block takes the whole coinbase. Expected value is correct.

**Its variance is not a reduction — it is exactly solo mining.** With share `s` and pool block rate
`λ`, your payment events arrive at `s·λ` = your hashrate ÷ network hashrate, each paying a full
coinbase: the same Poisson process, with the same payout, as mining alone. True PPLNS pays `s·R` on
**every** pool block, so its variance is `s` times solo's — and **that factor `s` is the entire
reason pools exist.** A cap-1 lottery pool sells convenience and nothing else.

So the correct end state is the cap raise, and this baton is its unavoidable prerequisite: **even at
cap N the RPC must accept a payee list — today it only reports one.** Design the wire and the pool
call as a list now, and the cap raise changes a constant and a boundary height, touching no API.

---

## 2. The four seams, with line numbers taken from `main` at `76465ce` by grep, not from memory

**(a) `crates/qumbra-node/src/mine_rpc.rs:62` — `MineTemplateWire`** carries a flat pair:

```rust
pub coinbase: u64,
pub coinbase_rkm: String,
```

and `MineBlockWire` (`:79`) carries the same pair for the submit direction. Both need the list.

**(b) `crates/qumbra-node/src/run.rs:2147` — `serve_mine_template`** takes no arguments and calls
`assemble_block()`, which bakes the node's own `miner_rkm`. This is the function that must accept
the requested payees.

**(c) `crates/qlab-p2p/src/adapter.rs:1890` — `assemble_block`**, the shared assembly path the
template RPC was deliberately built to reuse (#511). It needs a payee-parameterised sibling.
🔴 **The node's own mining must be byte-identical after your change** — it is the same function.
Prove it, do not assert it.

**(d) `crates/qumbra-pool/src/node_rpc.rs:24` `TEMPLATE_PATH` / `template_from_wire` at `:201`, and
`crates/qumbra-pool/src/pool.rs:819` `issue_job`.** The pool already has the list: `payee::
assemble_coinbase` is correct, tested, and **consumed by nothing on the submit path** — a read-only
accessor at `pool.rs:241` and two unit tests. Wire it up. That is the deliverable's whole point.

---

## 3. 🔴 The hazard that will bite you, named in advance

**`run.rs:2147` caches the template on `(tip, mempool_len)`** (`CachedMineTemplate`, `run.rs:342`).
Once the payee is a request parameter, **that key is wrong**: two miners asking at the same tip get
one cached template, and the second one is handed **the first one's payee**. It will not fail a
test you did not write, it will silently pay the wrong person, and it is exactly the class of defect
#553 exists to close.

**The payee list must be part of the cache key, or the cache must not be consulted for
payee-bearing requests.** Say in the PR which you chose and why. A test that asks twice with
different payees and asserts the two templates differ is the minimum.

---

## 4. Rules for this baton

- 🔴 **NO `cargo test` on this machine, at any scope — not one test.** `cargo check` and
  `cargo clippy` are the only local verification you may run. Write the tests, push the branch,
  apply the **`verify-graviton`** label; CI is the bar and the only place tests execute.
- Worktree + PR. Never push to `main`.
- **Existing bytes on `/v1/mine/template` and `/v1/mine/block` change ⇒ bump `RPC_VERSION`.**
  That is the house rule (PR #315, #317): a changed surface bumps, a pure route addition does not.
  You are changing existing surfaces.
- **Backward compatibility is NOT owed here and do not spend effort on it.** The only two consumers
  are `qumbra-pool` (in this repo, you are changing it) and the fleet's own nodes (rolled together).
  A compat shim for a payee-free request is a second code path with no second caller.
- The cap stays 1. `check_scheduled_coinbase_payees` (`qlab-devnet/src/body.rs:689`) already sums
  arbitrary-length lists in u128 and refuses over-cap lists by name — **do not touch it.**
- Every claim in your PR body that is checkable, check. If you cannot, say you did not.

## 5. What acceptance will ask

1. **Same tree** — the CI run's `headSha` equals the PR's `headRefOid`.
2. **Counts reconcile** — main's baseline plus exactly your new tests, stated as arithmetic.
3. **Negatives zero** — `FAILED` (case-sensitive), `panicked at`, `^error`.
4. **The node's own mining is unchanged** — named test or golden, not an assertion in prose.
5. **The cache hazard in §3 has a test that would fail without your fix.**
6. **A pool-side test that a block assembled for payee P declares P**, through
   `assemble_coinbase` → template request → `issue_job` → the body that `submit_block` would send.
   The tautology to avoid: asserting the template's payee equals the payee we asked for proves the
   echo, not the path. Assert on the **body handed to submit**.
