# `qumbra-pool` — a custody-free mining pool

> [中文版](README-zh.md) · English is authoritative on technical detail.
> 🔴 **`pool.qumbra.org:3333` is OPEN to the internet and serving.** Measured 2026-08-25: a
> stratum login from an ordinary outside laptop was answered with a real job. It has paid miners
> (137 blocks on 2026-08-22) and it is **unannounced but not unreachable** — see §*Reachability*,
> which corrects the opposite claim this line carried on 2026-08-24.

## Status board

Rows flip ⬜ → ✅ only when the coordinator has accepted the thing, never when it is
merely written. Last updated **2026-08-24 15:32 +08**.

> 🔴 **Correction, 2026-08-24 — this document contradicted itself for two days.** Its headline
> said *"does not pay yet"* and its own table said the pool paid 137 blocks. The 🔴 paragraphs
> under *Bring-up* were written 2026-08-21 and were **superseded on 2026-08-22**, but nobody
> came back to mark them, so a reader met the old verdict first and the new evidence second.
> The superseded text is kept below **under a dated banner rather than deleted** — the 08-21
> reading was correct when it was written and the reasoning in it is still worth having. What
> is fixed here is that it no longer reads as current.

### The software — COMPLETE

| item | state |
|---|---|
| Stratum mapping + `qlab-stratum` protocol crate | ✅ 2026-08-18 (lab PR #484) |
| TCP stratum endpoint, form-keyed template source | ✅ 2026-08-19 (lab PR #494) |
| RandomX share-PoW · PPLNS window · V5 payee assembly | ✅ 2026-08-19 (lab PR #499) |
| XMRig e2e drill + five named adversarial refusals | ✅ 2026-08-19 (lab PR #500) |
| Stock-XMRig-compatible work value (trailing-8-LE) | ✅ 2026-08-19 (lab PR #492, issue #490) |
| Node mine RPC (`/v1/mine/template`, `/v1/mine/block`) + pool binary in the image | ✅ 2026-08-20 (lab PR #513, issue #511) |

### Bring-up — ran, broke, was repaired, and has paid. 2026-08-21 → 08-23

| item | state |
|---|---|
| Refuse-to-mislead gate (static template / null payout) | ✅ 2026-08-20 (lab PR #523) |
| svc1 config on `node_rpc`, entrypoint `pool` path, `template_serving` | ✅ 2026-08-21 (deploy #210, #213) |
| **svc1 has its own `qumbra-node`** — the faucet has no mine RPC on any revision | ✅ 2026-08-21 (deploy #215, lab #519) |
| Pool rolled onto svc1, `pool` profile enabled, SG opened on 3333 | ✅ 2026-08-21 |
| **🎉 First real share accepted end-to-end from stock XMRig** | ✅ **2026-08-21 00:56 +08** |
| **🎉 A miner paid by this pool** | ✅ **first at height 1776**, 2026-08-22 01:19 +08; **137 blocks over the following 3 h**, and **0** to the pool's own address — lab #553 CLOSED |
| Public stratum on `pool.qumbra.org:3333` | ▶️ **restarted 2026-08-22 01:12 +08** — it can pay now |
| 🔴 **Outage: the pool could not read its node's template at all** | fixed 2026-08-23 (lab PR #628, issue #626) |

**The 08-23 outage, recorded because the failure mode is reusable.** `tiny_http` switches to
chunked transfer above `chunked_threshold().unwrap_or(32768)` (`response.rs:246`), and
`chunked_transfer::Encoder` emits 8,192-byte chunks — hex `2000`. The pool's node-RPC client took
everything after `\r\n\r\n` verbatim and handed it to serde, which read the **chunk-size line** as
the document:

```
invalid type: integer 2000, expected struct MineTemplateWire at line 1 column 4
```

So the pool served nothing the moment a template crossed 32 KB. **PR #628 lifted framing into
`qlab-http-framing` and fixed all four hand-rolled clients**, not just this one — the same
take-the-bytes-after-the-header shape existed in three other places. Verified live after the roll:
serving, zero parse failures.

The share, from hel1, on the **unmodified** `xmrig-6.22.2-linux-static-x64` release tarball with a
64-hex rkm as the login — so this is the **miner-payee** branch, not the pool's fallback:

```
[16:56:41.940]  net      new job from pool.qumbra.org:3333 diff 1024 algo rx/0 height 610
[16:56:42.232]  cpu      READY threads 1/1 (1) huge pages 100% 1/1 memory 2048 KB
[16:56:59.796]  cpu      accepted (1/0) diff 1024 (179 ms)
```

Eighteen seconds from `READY` to an accepted share, against the public endpoint, with nothing patched.

---

> ### ⏳ SUPERSEDED — the reading as of 2026-08-21 21:39 +08
>
> **Everything between this banner and the next horizontal rule was true when written and is not
> true now.** It was overtaken on 2026-08-22 01:19 by the pool paying a miner at height 1776, and
> then 137 blocks in three hours. It is kept because two of its arguments outlived their verdict:
> that a payee tally cannot separate pool-paid from solo-mined when the same rkm does both, and
> that obscurity was never the control on the open port. **Do not quote the ALL-CAPS verdicts
> below as the state of the pool.**

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

---

**End of the superseded 08-21 reading.** What actually settled it: on 2026-08-22 the mine-RPC
gained a payee parameter (lab PR #588, issue **#553 CLOSED**), the pool paid a miner at
**height 1776, 01:19 +08**, and over the next three hours **137 of 324 blocks paid the miner and
0 paid the pool's own address**. The 08-21 warning about payee ambiguity was **honoured** in that
test — it is what made "137 to the miner, 0 to the pool" evidence rather than a coincidence.

### Between here and a pool anyone should be told about

| item | state | blocked on |
|---|---|---|
| A block actually mined, and its payee read | ✅ **done at scale** | 08-21: three blocks, all paying the pool. 08-22: **137 of 324** paid the miner, **0** paid the pool. |
| Connection cap, line bound, rate limit on public stratum | ✅ 2026-08-21 (PR #563, lab #544) |  |
| Bounded staleness on the held template | ✅ 2026-08-21 (PR #549, lab #545) |  |
| An unowned payee cannot reach the chain **from the pool** | ✅ 2026-08-21 (PR #554, the pool half of lab #547) |  |
| **The pool can pay a miner at all** | ✅ 2026-08-22 (lab PR #588, observed at height 1776) |  |
| 🔴 **The pool can pay MORE THAN ONE miner** | ⬜ | **the `11_520` payee-cap boundary** — see below. This is the gate a second miner runs into, and it was missing from this table until 2026-08-24. |
| The node refuses to mine without a `miner_rkm` | ▶️ **in flight** 2026-08-24 (Multica QUM-173) | **lab #552(a)** — why the unspendable placeholder was expressible |
| Admissions are attributable to a source | ⬜ | **lab #584** — the counters count, they do not attribute |
| Public announcement of the endpoint | ⬜ | **Larry's call, and it is now the only thing on this row.** #553 is closed — the pool pays. |

**Both of the issues that once held this row are fixed** (#544 caps connections, line length and
per-connection deadlines, PR #563; #545 was two defects — the poll thread discarded jobs
`replace_template` had already built, so a miner got work at login and never again, and a held
template had no staleness bound — PR #549). Neither was ever a risk to the chain or to any key;
both were ways a miner burns electricity for nothing.

~~🔴 **What replaced them is worse, and it is not a hardening gap: the pool cannot pay anyone
(#553).**~~ **Struck 2026-08-24: #553 is closed and the pool has paid.** That sentence was written
2026-08-21 and stood for a day.

⚠️ **The reasoning this paragraph retired is still retired.** It once said the exposure was
acceptable because the endpoint was *unadvertised*. **Obscurity is not a control** — the exposure
was bounded by the security group, and stopping the container is what actually closed the port.
Bringing it up means **narrowing the SG first, then starting the profile**, in that order.

### 🔴 Why a second miner cannot be invited yet — the payee cap

**Today a block can pay exactly one address, and the pool gives that address the whole reward.**

```rust
// crates/qlab-devnet/src/body.rs
pub const COINBASE_PAYEE_CAP_V5: usize          = 8;
pub const COINBASE_PAYEE_CAP_V5_AT_BIRTH: usize = 1;
pub const COINBASE_PAYEE_CAP_V5_BOUNDARY_HEIGHT: Option<u64> = Some(11_520);
```

T2 measured **tip 4,802** on 2026-08-24 15:49 +08 (`explorer.qumbra.org/v1/health.json`), so the
active cap is **1**. `payee::pick_payees` then sorts the PPLNS window by weight, truncates to the
cap, and hands the **entire** mint to whoever is first:

```rust
scored.sort_by(|a, b| b.1.cmp(&a.1));
scored.truncate(cap);
if scored.len() == 1 || cap == 1 {
    return vec![CoinbasePayee { rkm: scored[0].0, amount }];   // the whole thing
}
```

**This is a known and deliberate state, not a defect** — `payee.rs`'s module doc says *"Before
activation, PPLNS cannot split the mint"* and the test is called
`v5_birth_cap_is_one_so_the_winner_takes_the_mint`.

### 🔴 It is not hypothetical — it has been running since 2026-08-22 12:19, and it is worse than "a small miner loses"

**Two of our own miners have been on this pool concurrently for over 23 hours** — two stock XMRig
processes on `hel1`, two distinct payout logins, **identical hardware, identical binaries, one
thread each, ~27 H/s apiece**. Lifetime accepted shares within **2 %** of one another (2,730 vs
2,783). Both keys were published on lab #553 **before either rig connected**, each with a
full-chain absence proof, so the identity claims below do not rest on anyone's say-so.

**What they earned:**

| window | | |
|---|---|---|
| 2026-08-22 ~17:47, 60 blocks | `m2` = **28** | `m1` = **3** |
| 2026-08-22 ~22:19, 60 blocks | `m2` = **0** | `m1` = **32** |
| 2026-08-24, last 120 blocks | `m2` = **55** | `m1` = **1** |

**Two miners of exactly equal size, taking turns shutting each other out for hours at a time.** The
payout flips when the trailing-1,024-share PPLNS window tips, and until it tips the leader takes
**everything**. At one point `m2` had performed *more* total work than `m1` and had earned nothing
since mid-afternoon.

**So "a smaller miner earns less" understates it, and understates it in a misleading direction.**
It invites the reading that proportionality merely degrades at the margins. **What actually happens
is winner-take-all between equals**, in multi-hour regimes, with the loser's electricity spent for
nothing until the window flips. **That is what a stranger would be joining.**

**No stranger has ever mined this pool** — both logins are ours, and that is the only reason this
has cost nobody anything so far.

### 🔴 The boundary is a whole-fleet consensus roll, and inviting the second miner is what triggers it

From the constant's own doc comment:

> **This is a consensus rule change and the roll is the whole fleet, not one host.** Above the
> boundary a block may carry more than one coinbase payee; a node still on an older binary rejects
> such a block and forks off. Unlike the 8,640 emission boundary this is a **no-halt** crossing, so
> there is no halt to catch a straggler — every validating host must carry this constant *before*
> `11_521`.

**The practical risk window is narrower than the rule, and that is exactly the trap:** nothing forks
until a block actually names two or more payees, **which happens only when the PPLNS window has two
or more winners.** So *"a second miner joins"* and *"the fork becomes possible"* are the same event.
The order cannot be reversed.

**Runway**: 11,520 − 4,802 = **6,718 blocks**, ≈ **5.8 days** at the 75 s target — boundary around
**2026-08-30**. Deliberately generous, and it is measured from a tip that moves.

**Owed before then, and it is an on-host read, not a repo read: confirm every one of the six hosts
is running a binary that carries `Some(11_520)`.** A host whose *file* has it and whose *process*
does not is the failure this project has already paid for once.

### The sequence, in order

1. **Roll the fleet** to a binary carrying the `11_520` constant — all six hosts, verified against
   the running process.
2. **Cross the boundary** (~2026-08-30). Until then the cap is 1 whatever the pool does.
3. **Fix [#584](https://github.com/qumbra-labs/qumbra-lab/issues/584)** — admissions must be
   attributable. With only our own miners this cost four sessions four hours; with strangers on the
   port you cannot tell a miner from an abuser, or answer a single complaint.
4. **Decide the fee policy.** Nobody has. A stranger must be told what they are paying.
5. **Then, and only then, the announcement is a live question** — and it is Larry's.

### 🔴 Reachability — the endpoint is OPEN to the internet and serving

**Measured 2026-08-25 11:25 +08 from an ordinary laptop outside the fleet.** A stratum `login`
with an arbitrary name was answered with a **real job for a real height**:

```
nc -vz 54.243.254.140 3333   ->  succeeded

{"id":1,"jsonrpc":"2.0","result":{"id":"s00000012","job":{
  "algo":"rx/0","height":5737,"job_id":"j00000fae",
  "blob":"1591123cb6e4…","seed_hash":"d1e28adcce8f…"}}}
```

**Anyone who knows the hostname can connect and be given work today.** `pool.qumbra.org` resolves
to `54.243.254.140` (AMAZON, DNS-only — no Cloudflare in front, unlike `seed.qumbra.org`), and
nothing between the internet and the stratum port refuses a stranger.

> ⏳ **CORRECTION, 2026-08-25.** The version of this section merged on 2026-08-24 stated the
> opposite — that TCP 3333 *"times out"*, that *"silence is the signature of a security-group
> DROP"*, and that an outside probe therefore could not tell a running pool from a stopped one.
> **All of that was false.** It rested on one probe,
> `bash -c 'exec 3<>/dev/tcp/pool.qumbra.org/3333' 2>/dev/null`, which **hangs** against this
> endpoint and was killed by its own `timeout` — with stderr discarded, so the silence was read
> as a fact about the service. A control run the next day settles it: the same construct against
> `seed.qumbra.org:443` returns instantly, so `/dev/tcp` works here and the failure was specific
> to that probe. **`nc` and a stratum login both succeed.**
>
> The lesson is the one this repo keeps paying for: **a probe that fails silently and a service
> that is down are the same reading.** Suppressing stderr on a probe that can hang converts "my
> instrument did not work" into "the thing is not there."

**So "unannounced" is the only thing standing between a stranger and this pool — and this document
already says obscurity is not a control.** That was written about the exposure window before the
endpoint was stopped; it applies unchanged now, with the port open again.

**What that means today, given the payee cap above:** a stranger who connects gets hours of the
entire mint and hours of nothing, uncorrelated with what they contributed in that period. **The
gate on announcing is not the only thing protecting them — the security group would be, and it is
not narrowed.**

> **DECIDED 2026-08-25 14:10 +08 — Larry: leave it open and unannounced.** The coordinator
> recommended narrowing the security group until the payee-cap boundary passes; that recommendation
> was declined and this is the deliberate position, not an oversight.
>
> **What it accepts:** the port stays reachable from the internet, the only protection is that the
> hostname is not published — *and obscurity is not a control, as this document says two paragraphs
> up* — and a stranger who does connect meets the cap-1 payout with nothing telling them it is
> expected, in a pool that [cannot record who they were](https://github.com/qumbra-labs/qumbra-lab/issues/584).
>
> **What bounds it:** the payee cap ends by rule at height **11,520**, which was **5,638 blocks —
> about 4.9 days** — away when this was decided (T2 tip 5882). Above it `pick_payees` splits
> proportionally across up to eight winners.
>
> **What it does not decide:** announcing. That remains gated on the boundary, on #584, and on a
> fee policy. **This decision is about the door, not the invitation** — a distinction that only
> became visible today, when a broken probe of the coordinator's was corrected and the endpoint
> turned out to have been open all along.

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
