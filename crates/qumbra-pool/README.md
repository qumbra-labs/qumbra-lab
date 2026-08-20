# `qumbra-pool` — a custody-free mining pool

> [中文版](README-zh.md) · English is authoritative on technical detail.
> **`pool.qumbra.org:3333` resolves but does not pay yet — see the status board below.**

## Status board

Rows flip ⬜ → ✅ only when the coordinator has accepted the thing, never when it is
merely written. Last updated 2026-08-20 16:5x +08.

### The software — COMPLETE

| item | state |
|---|---|
| Stratum mapping + `qlab-stratum` protocol crate | ✅ 2026-08-18 (lab PR #484) |
| TCP stratum endpoint, form-keyed template source | ✅ 2026-08-19 (lab PR #494) |
| RandomX share-PoW · PPLNS window · V5 payee assembly | ✅ 2026-08-19 (lab PR #499) |
| XMRig e2e drill + five named adversarial refusals | ✅ 2026-08-19 (lab PR #500) |
| Stock-XMRig-compatible work value (trailing-8-LE) | ✅ 2026-08-19 (lab PR #492, issue #490) |
| Node mine RPC (`/v1/mine/template`, `/v1/mine/block`) + pool binary in the image | ✅ 2026-08-20 (lab PR #513, issue #511) |

### Between here and a pool that pays — NOT DONE

| item | state | blocked on |
|---|---|---|
| Refuse-to-mislead gate (static template / null payout) | ⬜ PR #523 open, CI running | review |
| svc1 config rewritten to `node_rpc` (not the static fixture) | ⬜ not started | lab #519 |
| Entrypoint `pool` path used instead of overridden | ⬜ not started | lab #519 |
| Pool rolled onto svc1, compose profile enabled | ⬜ not started | the two rows above |
| **First real share accepted end-to-end from stock XMRig** | ⬜ | everything above |
| Public announcement of the endpoint | ⬜ | the row above — the endpoint is announced only when it pays |

### Ruled out of scope for now — deliberately, not forgotten

| item | state | note |
|---|---|---|
| Operator fee policy | ⬜ no ruling exists | nobody has decided what a pool charges |
| More than one payee per block | ⬜ `COINBASE_PAYEE_CAP_V5 = 1` | raising the cap is a **rule change**, not config |
| Third-party pool operator guide (public) | ⬜ | written after we have run one ourselves, not before |
| Audit | ⬜ | the pool is in the audit RFP's scope, unstarted |

### Prerequisites already satisfied

| item | state |
|---|---|
| T2 live with the v5 payee-list coinbase | ✅ 2026-08-20 14:00 +08 |
| `pool.qumbra.org` DNS (grey-cloud — stratum is raw TCP) | ✅ 2026-08-20 |
| Pool payout wallet generated, `payout_rkm` known | ✅ 2026-08-20 |
| svc1 SG open on 3333/tcp | ✅ 2026-08-20 (deploy #197) |

**One sentence for anyone skimming: the pool is built and proven against fixtures; it is
not deployed, and no miner has ever been paid by it.**

## What makes this pool different

A conventional mining pool receives the block reward and then owes its miners their
share. That debt is the pool's power and the miner's risk: the pool custodies your
earnings between the block and the payout, and a pool that vanishes takes them with it.

Qumbra's block reward is a **payee list inside consensus** (`CoinbasePayee`, the T2 v5
body form). The block itself pays each miner directly, in the coinbase, at the moment it
is accepted. **The pool never holds miner funds** — it decides the split and assembles
the block, but the chain does the paying. A pool operator who disappears mid-round costs
you the round, not your balance.

That is the whole reason the payee-list coinbase exists, and it is why this crate is
worth reading rather than just running: **anyone can operate one of these**, and the
design is only meaningful if more than one person does.

## Shape

```
  XMRig ──stratum/TCP──▶ qumbra-pool ──HTTP──▶ qumbra-node ──▶ the chain
        login/job/submit              GET /v1/mine/template
                                      POST /v1/mine/block
```

- **Miner side**: ordinary Monero-family stratum. Stock XMRig speaks it unmodified — see
  [`docs/stratum-primer.md`](../../docs/stratum-primer.md) for what that protocol is and
  [`docs/pool-stratum-mapping.md`](../../docs/pool-stratum-mapping.md) for the
  field-by-field mapping, including the named deviations.
- **Chain side**: the pool asks its own node for a block template and hands completed
  blocks back. Both routes are off by default and require `template_serving = true` in
  the node's config — a pool operator runs their own node and turns them on for it.
- **Share validation** uses `qlab_devnet::pow::satisfies_target_for` — the same predicate
  consensus uses — with the v5 trailing-8-bytes-LE work value (lab #490). The pool applies
  XMRig's strict `<` at the *share* filter and consensus's `<=` for block candidacy; the
  difference is deliberate and test-locked.
- **Accounting** is PPLNS over the last `PPLNS_WINDOW_SHARES = 1024` accepted shares
  (`[devnet-placeholder]` — not a frozen parameter).

## Configuration

See [`qumbra-pool.example.toml`](qumbra-pool.example.toml) for the annotated file. The
fields that matter:

| field | meaning |
|---|---|
| `listen_addr` | where stratum listens. `3333` is conventional. |
| `share_difficulty` | the share target handed to miners; below chain difficulty by design |
| `node_rpc` | your node's mine-RPC base URL. **This is the real template source.** |
| `poll_ms` | how often to re-ask for a template (job re-issue follows tip changes) |
| `payout_rkm` | the pool's own payout identity, from `qumbra-wallet miner-rkm` |
| `[template]` | a **static fixture** for tests only — see the refusal below |

### Two refusals you should expect, and want

A pool that looks alive while doing nothing useful is worse than a pool that will not
start, because miners spend real electricity on it. So, before the listener binds:

- **a static `[template]` is refused for service** (`static-template-source-refused`). A
  fixed height and prev can look perfectly healthy while tracking no chain at all: jobs
  issue, shares credit, and not one of them can ever become a block.
- **an all-zero or unusable `payout_rkm` is refused.** Coinbase paid to a null identity
  is unspendable by anyone, including the miners who earned it.

Both are checked by `check` and by `run`, before any RPC connection or listener bind.
*(Landing in lab #519's first PR; the mechanism is described here because it is the
intended contract, not because it is optional.)*

## Running one

```sh
qumbra-pool check --config pool.toml   # config, refusals, template source — no listener
qumbra-pool run   --config pool.toml   # serve
```

You also need a `qumbra-node` of your own with `template_serving = true`. The mine RPC is
container-internal by design: the pool reaches the node over a private network, and
**the node's mine routes are never published to the public internet** — only the stratum
port is public.

## Records

Design: `qumbra-design/pool-t1-brief.md` (route A, the stratum-compatible header ruling)
and `pool-payout-axis-brief.md` (why option (c), the versioned payee list). Build: lab
#482 (stages 0–3), #490 (the work-value predicate that makes stock XMRig work), #511 (the
node mine RPC), #519 (bring-up).
