# What is stratum? — a two-minute primer

> [中文版](stratum-primer-zh.md) · Reader: anyone who wants to mine Qumbra through the
> pool without running a node, or anyone reading [pool-stratum-mapping.md](pool-stratum-mapping.md)
> and wondering what the protocol underneath is. Written 2026-08-19 (Larry asked; the
> answer was worth keeping).

**Stratum is the protocol miners and mining pools use to talk to each other.** The name
is Latin for "layer" — coined in the 2012 Bitcoin community, no deeper meaning, and it
stuck as the de-facto standard's name. Qumbra speaks the Monero-family dialect, the one
built into stock XMRig.

## How it works

One long-lived TCP connection, JSON lines back and forth:

1. **login** — the miner checks in ("here's my wallet, algorithm `rx/0`"); the pool
   answers with a session id and the first job.
2. **job** (pool → miner) — a work template: for Qumbra that is the **97-byte v5 block
   header** (the "blob"), plus a share target and the RandomX seed. Before handing it
   out, the pool writes a per-connection **extra-nonce** into blob bytes 43–46, so no
   two miners ever grind the same search space.
3. The miner spins nonces in its own window (blob bytes 39–42) and computes RandomX
   hashes.
4. **submit** (miner → pool) — any hash that clears the share target goes back.

A **share** is proof-of-effort: its difficulty is far below a real block's, so a miner
submits one every few seconds, and the pool counts shares to split rewards by
contribution (Qumbra's pool uses a PPLNS window). Occasionally a share is good enough
to clear the **chain's real difficulty** — that is a block: the pool assembles it (the
payee-list coinbase carries each miner's cut) and submits it to the network.

## Why it matters to Qumbra

**Stock XMRig speaks stratum out of the box.** Route A's whole bet is "not one line
changes on the miner side" — which is why the T2 v5 header was designed backwards from
stratum's habits (the nonce moved to bytes 39–46, exactly XMRig's expected window), and
why the [#490](https://github.com/qumbra-labs/qumbra-lab/issues/490) work-value fix was
the other half of the same bet (which hash bytes XMRig reads when judging a share).
The end state: download XMRig, point it at `pool.qumbra.org:3333` with a payout
address, and you are mining Qumbra.

Deeper reading: [pool-stratum-mapping.md](pool-stratum-mapping.md) (the field-by-field
protocol mapping), `crates/qumbra-pool/` (the pool implementation), lab #482 (the
build record).
