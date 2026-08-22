# `qumbra-pool` — a custody-free mining pool

> [中文版](README-zh.md) · English is authoritative on technical detail.
> **`pool.qumbra.org:3333` resolves but does not pay yet — see the status board below.**

## Status board

Rows flip ⬜ → ✅ only when the coordinator has accepted the thing, never when it is
merely written. Last updated 2026-08-22 07:25 +08.

### The software — COMPLETE

| item | state |
|---|---|
| Stratum mapping + `qlab-stratum` protocol crate | ✅ 2026-08-18 (lab PR #484) |
| TCP stratum endpoint, form-keyed template source | ✅ 2026-08-19 (lab PR #494) |
| RandomX share-PoW · PPLNS window · V5 payee assembly | ✅ 2026-08-19 (lab PR #499) |
| XMRig e2e drill + five named adversarial refusals | ✅ 2026-08-19 (lab PR #500) |
| Stock-XMRig-compatible work value (trailing-8-LE) | ✅ 2026-08-19 (lab PR #492, issue #490) |
| Node mine RPC (`/v1/mine/template`, `/v1/mine/block`) + pool binary in the image | ✅ 2026-08-20 (lab PR #513, issue #511) |

### Bring-up — the software ran in production, and then stopped working. 2026-08-21

| item | state |
|---|---|
| Refuse-to-mislead gate (static template / null payout) | ✅ 2026-08-20 (lab PR #523) |
| svc1 config on `node_rpc`, entrypoint `pool` path, `template_serving` | ✅ 2026-08-21 (deploy #210, #213) |
| **svc1 has its own `qumbra-node`** — the faucet has no mine RPC on any revision | ✅ 2026-08-21 (deploy #215, lab #519) |
| Pool rolled onto svc1, `pool` profile enabled, SG opened on 3333 | ✅ 2026-08-21 |
| **🎉 First real share accepted end-to-end from stock XMRig** | ✅ **2026-08-21 00:56 +08** |
| **🎉 A miner paid by this pool** | ✅ **first at height 1776**, 2026-08-22 01:19 +08; **137 blocks over the following 3 h**, and **0** to the pool's own address — lab #553 CLOSED |
| Public stratum on `pool.qumbra.org:3333` | ▶️ **restarted 2026-08-22 01:12 +08** — it can pay now; SG still `0.0.0.0/0`, deliberately, Larry's call |

The share, from hel1, on the **unmodified** `xmrig-6.22.2-linux-static-x64` release tarball with a
64-hex rkm as the login — so this is the **miner-payee** branch, not the pool's fallback:

```
[16:56:41.940]  net      new job from pool.qumbra.org:3333 diff 1024 algo rx/0 height 610
[16:56:42.232]  cpu      READY threads 1/1 (1) huge pages 100% 1/1 memory 2048 KB
[16:56:59.796]  cpu      accepted (1/0) diff 1024 (179 ms)
```

Eighteen seconds from `READY` to an accepted share, against the public endpoint, with nothing patched.

🔴 **AND THEN IT STOPPED, AND THE POOL IS STOPPED NOW.** That miner had **2 shares accepted and 38
rejected**. After the second share the pool never issued another job — it builds them correctly on
every tip change and discards them (**lab #545**) — so every share for the next eleven minutes was
rejected by the pool's own `stale job` verdict, with no disconnect and no message.

🔴 **THE POOL HAS PAID NOBODY. It has produced ZERO blocks.** Neither accepted share became one:
both fall inside the 133-second gap between block 611 (16:57:00) and block 612 (16:59:13). Blocks
on chain paying that miner's rkm came from **its own solo-mining node**, which has run since
07:13 UTC — nine hours before the pool existed. **The payee alone cannot distinguish pool-paid from
solo-mined, because the same rkm was used for both, and a tally that cannot separate them is not
evidence about either.** A future test of this path must use a payout rkm **nothing else mines to**.

🔴 **Three blocks on T2 pay the node template's placeholder `0111011101110111…`, which nobody can
spend** (~15 QMB), and the pool's own rkm — the fallback `payee.rs` documents — took **zero of 61
blocks** across a window where the PPLNS window was certainly empty (**lab #547**). The pool was
stopped the moment this was seen and stays stopped.

**What IS proven: the stratum leg.** Login, job, share accepted, ~264 ms round trip, unmodified
stock XMRig against a public endpoint. **What is NOT proven: that this pool can pay a miner.**

### Between here and a pool anyone should be told about — NOT DONE

| item | state | blocked on |
|---|---|---|
| A block actually mined, and its payee read | ✅ **done at scale** | 08-21: three blocks, all paying the pool. 08-22: **137 of 324** paid the miner, **0** paid the pool. |
| Connection cap, line bound, rate limit on public stratum | ✅ 2026-08-21 (PR #563, lab #544) |  |
| Bounded staleness on the held template | ✅ 2026-08-21 (PR #549, lab #545) |  |
| An unowned payee cannot reach the chain **from the pool** | ✅ 2026-08-21 (PR #554, the pool half of lab #547) |  |
| **The pool can pay a miner at all** | ✅ 2026-08-22 (lab PR #588, observed at height 1776) |  |
| The node refuses to mine without a `miner_rkm` | ⬜ | **lab #552** — why the unspendable placeholder was expressible |
| Admissions are attributable to a source | ⬜ | **lab #584** — the counters count, they do not attribute |
| Public announcement of the endpoint | ⬜ | **lab #553 first.** Announcing a pool that cannot pay is the one thing we must not do |

**Both of the issues that once held this row are fixed** (#544 caps connections, line length and
per-connection deadlines, PR #563; #545 was two defects — the poll thread discarded jobs
`replace_template` had already built, so a miner got work at login and never again, and a held
template had no staleness bound — PR #549). Neither was ever a risk to the chain or to any key;
both were ways a miner burns electricity for nothing.

🔴 **What replaced them is worse, and it is not a hardening gap: the pool cannot pay anyone
(#553).** The endpoint was stopped 2026-08-21 21:39 +08 and stays stopped until that lands.

⚠️ **And retire the reasoning this paragraph used to carry.** It said the exposure was acceptable
because the endpoint was *unadvertised*. **Obscurity is not a control** — the exposure was bounded
by the security group, which is still open to `0.0.0.0/0`, and stopping the container is what
actually closed the port. Restarting means **narrowing the SG first, then starting the profile**,
in that order.

### Ruled out of scope for now — deliberately, not forgotten

| item | state | note |
|---|---|---|
| Operator fee policy | ⬜ no ruling exists | nobody has decided what a pool charges |
| More than one payee per block | 🧊 max 8 built; boundary unset, so active cap remains 1 | height-keyed **rule change**, not config; activation is a later rollout stamp |
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

✅ **THAT IS THE DESIGN, AND AS OF 2026-08-22 01:19 +08 IT IS ALSO WHAT THIS POOL DOES.** Height 1776 paid `daf76f16…` — a miner's own key, posted publicly at tip 1771 thirteen seconds before the rig connected, and proven absent from all 1,772 prior heights. 4.992690888 QMB, paid by the chain, never held by the pool.

**The retired 🔴 block is kept below, because a doc that deletes the state it was in teaches nobody what was wrong:**

> 🔴 **THAT IS THE DESIGN. IT IS NOT WHAT THIS POOL DOES TODAY.** `GET /v1/mine/template`
> **reports** a payee, it does not **accept** one — and the payee is bound into the header the
> miner grinds against, so it cannot be substituted once a share comes back. **Every block this
> pool can submit pays the poolnode's `miner_rkm`, whatever the PPLNS window says.**
> `payee::assemble_coinbase` — the winner selection, the empty-window fallback, the cap — is
> correct and is **not on the submit path**; its only consumers are a read-only accessor and two
> unit tests. **So the pool is custodial right now: it earns the coinbase to its own address and
> has no mechanism to pay anyone.** Tracked as [lab #553](https://github.com/qumbra-labs/qumbra-lab/issues/553),
> which is the gate on this endpoint being announced to anybody.
> 
> **Measured, not inferred** (2026-08-21, first live session): a rig mining 29 accepted shares
with a payout key **nothing else on the chain has ever mined to** was inside the PPLNS window
the whole time. Three blocks landed in that window. **All three paid the pool's own address;
the miner's key received zero.**

**Measured again, at scale** (2026-08-22, `1772..2095`, **324 of 324 heights verified covered**, both keys matched at their full 32 bytes):

| payee | blocks |
|---|---|
| `daf76f16…` — the miner's key, **published at tip 1771, 13 s before its rig connected** | **137** |
| `5f13e0c7…` — a solo miner | 39 |
| `d2c02c7c…` — a solo miner | 33 |
| **`79c3291d…` — the pool's own fallback address** | **0** |

**The zero is the sharper half.** The fallback is not losing the tally; it is never taken. And the run contains its own **negative control**, unplanned: during a 52-minute window in which the miner hashed zero, its key was paid **0 of 33** blocks and the pool produced none — so payment tracks work in both directions. The 137 figure spans that dead window, so it understates the rate while mining and **must not be read as a hashrate share**.

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
| `poll_ms` | how often to re-ask the node for a template (default 1000). On a tip change the pool replaces the held template, marks outstanding jobs stale, and **pushes a `job` notification** to each live session |
| `template_max_poll_failures` | consecutive failed polls before work is suspended (default 3) |
| `template_max_age_ms` | wall-clock without a successful poll before work is suspended. Unset, this is `template_max_poll_failures × poll_ms` so the bound tracks the poll cadence rather than a second literal |
| `template_disconnect_after_ms` | sustained wall-clock outage before suspended sessions end so miners can fail over (default 300000 ms / 5 min). Must be greater than the suspension age |
| `payout_rkm` | the pool's own payout identity, from `qumbra-wallet miner-rkm` |
| `max_connections` | concurrent stratum connections (default 64). Each one is a thread; past the cap the accept loop writes `connection-cap-reached` and does not spawn |
| `max_connections_per_ip` | concurrent connections from one IP. Unset, this is `max(1, max_connections / 8)` so one peer cannot occupy the whole cap |
| `max_line_bytes` | max bytes of one LF-terminated line (default 4096). Past it the connection is closed as `line-too-long` |
| `request_timeout_ms` | wall-clock to finish one line after its first byte (default 10000). Distinct from the 100 ms per-read timeout that drains the job outbox; this is what catches a trickling client |
| `connection_timeout_ms` | wall-clock from accept to the first complete line. Unset, this is `request_timeout_ms`. After a complete line, silence is a hashing miner and is not killed |
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
