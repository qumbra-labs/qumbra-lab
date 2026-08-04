# Joining and mining — the operator's path

中文: [`join-and-mine-zh.md`](./join-and-mine-zh.md) — EN is authoritative on technical detail.

**Status: written ahead of the T1 mint.** Everything here is exercisable today against a
private net; the two values only a public net can supply — the genesis file and the seed
list — are marked **[published at T1]**. This is testnet-plan §6's "join/mine docs" row.

## 1. What you need

| | |
|---|---|
| hardware | 2 vCPU / 2 GB RAM is proven (the T0 fleet is `t4g.small`); RandomX runs in light mode (~256 MB) |
| network | **outbound TCP only.** You do NOT need a public address, port forwarding, or NAT tricks — the net accepts outbound-only participants by decision (2026-07-26). |
| OS | Linux x86-64/aarch64 or macOS; the Linux-aarch64 RandomX build caveat is solved in the docker image |

## 2. Get the software

**Docker (recommended):** the node image is public on GHCR — no registry credential,
digest-pinned tags per release. **[published at T1: image tag + digest]**

**From source:** Rust stable + `cmake` + a C++ toolchain (RandomX builds a C++ library):

```sh
cargo build --release -p qumbra-node -p qumbra-wallet
```

## 3. Make a wallet, get your `miner_rkm`

Coinbase needs a payee. The wallet CLI produces both your addresses and the node-config form
of your mining identity:

```sh
qumbra-wallet keygen --dir ~/.qumbra-wallet     # seed (0600) + address [0]; prints NO key material
qumbra-wallet miner-rkm --dir ~/.qumbra-wallet  # → miner_rkm = "…64 hex…"
```

Back up the phrase (`qumbra-wallet backup --dir … --reveal`) **before** you mine anything.
The phrase is deliberately **not BIP-39** — no other wallet can restore it, and this one will
not restore other wallets' phrases.

## 4. The node config, knob by knob

```toml
data_dir     = "/var/lib/qumbra"        # chain store + snapshot; survives restarts
listen_addr  = "0.0.0.0:9400"           # inbound P2P — bound even if nobody can reach you
genesis_file = "/etc/qumbra/genesis.qmb"          # [published at T1]
expected_genesis_hash = "…"                       # [published at T1]
dial_peers   = ["seed1.example:9400", "…"]        # [published at T1]
mining       = true
miner_rkm    = "…the 64 hex from step 3…"
```

- **`expected_genesis_hash` is a refusal, not a checksum**: a node handed the wrong genesis
  does not start. The genesis file IS the network's identity.
- **`advertise_addr` — stated, not discovered.** A node never sees its own public address.
  Set it **only** if you have one and want inbound peers; leaving it unset means you are an
  outbound-only participant, which is fully supported. Do not guess a value: a wrong
  advertisement pollutes other nodes' address books.
- Peer discovery is automatic past the seeds (learned addresses persist in `peers.dat`);
  connection caps default 8 outbound / 32 inbound. You configure none of it for a first run.

## 5. Run, and read the one line that matters

The `TELEMETRY` line answers, in order of what an operator actually asks:

- **`mready=`** — the mine-readiness gate. A cold node **must not mine before it knows where
  the chain is** (a real defect, fixed): `mready=synced` means the gate cleared;
  `mready=unknown` means it is still finding peers — this is a node deliberately not mining,
  not a node failing to mine.
- **`tip=` / `final=` / `regime=`** — your height, the finalized height, and whether
  committee finality is live (`Final`) or the chain is in PoW-only degraded mode.
- **`dialable=n/known`** — how much of the net's address book you could actually reach.
  Low `dialable` with rising `known` is normal for an outbound-only node.

## 6. Your coinbase, honestly

- A block you win pays `miner_rkm` — that identity is your wallet's **address [0]** (or the
  index you chose). The note is real chain data: recoverable from the chain itself, by
  design.
- It **matures before it is spendable**: `COINBASE_MATURITY_BLOCKS` (frozen §2 — quoted from
  the constant, currently 144 blocks ≈ 3 h at the 75 s target). Enforcement is structural:
  an immature note has no tree leaf, so no wallet — yours or a thief's — can spend it early.
- 🔴 **Two things you cannot do yet, said plainly:**
  1. **Spend.** T1 transacting is gated on the dummy-input mechanism and the mint (lab #219 /
     #188). Mining and accumulating are unaffected.
  2. **See your coinbase balance in `qumbra-wallet scan`.** The scan surface trial-decrypts
     transaction outputs; coinbase notes are derived from chain data instead, and the CLI's
     coinbase-harvest surface is a named follow-up, not a hidden hole. Your coins are on
     chain and re-derivable; the wallet just cannot COUNT them for you yet.

## 7. When something looks wrong

`final=` frozen while `tip=` climbs is a committee stall, not a mining problem — keep mining;
the net recovers finality without your intervention. A wedged-looking node with
`schain=fork` in its journal is on a losing branch; historically these self-recover, and the
current work on that mechanism is public (lab #229). Restarting loses nothing that
`data_dir` holds.
