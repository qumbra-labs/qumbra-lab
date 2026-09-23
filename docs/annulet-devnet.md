# The Annulet devnet — B6 (lab #716)

[中文](annulet-devnet-zh.md)

The Annulet devnet is one sequencer, two followers and a fee-unit faucet, running the L2 chain form built in B1–B5 with the real L2 verifier. This page says how to run it, what its evidence proves, and what it does not prove.

> **Status.** The compose file is statically validated and has not been brought up by anyone yet. The journey's evidence is the lane test below (`verify-graviton`), not a running devnet. Bringing the compose up is a later, scheduled step.

## What is in it

- **The devnet genesis**, `AnnuletGenesisFile::devnet()`. It is deterministic, and its hash is pinned: `6f0978eb2c56d6967a8c0ade9d1096ab8c4e79a9d846de53e39613cb43ddf374` (5,230 B), reproduced byte-identically by two runs of `examples/annulet_devnet_genesis`. It contains:
  - a registry of two assets: asset 0 (Cloaked), and `USDT-test` at asset 1 (Hybrid, a dev issuer key, an empty freeze tree);
  - 16 **stock notes** of exactly one grant each, to the faucet's `rkm`. A stock note is worth `tier_p + tier_s` = 3. One grant spends one note whole: 2 go to the requester and 1 is the S fee. There is no change and no harvest;
  - one genesis-minted `USDT-test` note (1,000,000) to a dev **holder** key.
- **Dev keys only.** The sequencer seed, the faucet key, the holder key and the `USDT-test` issuer key are published in `qumbra_node::annulet_genesis::devnet`, as the committee rehearsal keys are. None of them may carry value.
- **`qumbra-node genesis annulet-devnet [--out DIR] [--sequencer-data-dir DIR]`** writes that genesis. With `--sequencer-data-dir`, it also writes the dev sequencer key file, which is what makes a node the producer.
- **`qumbra-faucet annulet --node-config FILE [--listen ADDR]`** runs the faucet: a keyless follower in process, its own discovery endpoint as the faucet's source, and `POST /v1/annulet/grant` taking an address string.
  - Its stock is the genesis notes its key owns, less every note whose nullifier is already on chain, so a restart never re-offers a granted note.
  - It refuses to start, by name, on an L1 genesis, on an Annulet genesis that is not the devnet's, and on a node that would be the sequencer.
  - It has no tickets and no rate limit: the stock is 16 grants.
- **`POST /v1/tx` decodes by form.** Before B6 the node's HTTP submit surface decoded the L1 tx wire, so an Annulet transaction could not be submitted over HTTP at all. It now uses `decode_tx_for(form, …)`.

## How to run it

**The evidence (the lane):** `verify-graviton` on the B6 PR runs the workspace suite, which includes the five B6 test files:

| test | what it shows |
|---|---|
| `qumbra-faucet/tests/annulet_journey.rs` | **The journey.** A sequencer and two followers over TCP loopback, all under the real `L2Verifier`: <br>1. The faucet refuses both L1 forms and reads 16 stock notes. <br>2. Two S grants go out: one to the holder, one to a fresh recipient. A restarted faucet then sees 14. <br>3. The holder sends `USDT-test` to the recipient (shape P, vPublic = 0). <br>4. The recipient **detects** both of its notes through a **follower's** `/v1/compact` + `/full`, and spends the `USDT-test` back (P), with witnesses read from that follower. Re-submitting that spend is refused. <br>At the end the three nodes agree on tip, commitment root and 8 nullifiers, and the holder finds its note on the other follower. 2 S + 2 P real proves. |
| `qumbra-node/tests/annulet_binary.rs` | The real `qumbra-node` binary: `genesis annulet-devnet` stages the devnet, byte-identical to the pin. `run` then comes up as producer under the real L2 verifier and serves the genesis notes and the `USDT-test` opening. `POST /v1/tx` decodes the Annulet wire, and SIGTERM exits cleanly. |
| `qumbra-faucet/tests/annulet_binary.rs` | The real `qumbra-faucet annulet`: it refuses a non-devnet genesis and a sequencer node, serves the 16-grant stock page, and refuses an undecodable address. No proving. |
| `qlab-p2p/tests/annulet_sync.rs` (b) | A joiner catches up 4,100 sealed blocks (two full 2,000-header batches of 3,462-B units plus a remainder) through the **default** rate limiter. The full batch fits `MAX_PAYLOAD` and one inbound byte burst. |
| `qlab-p2p/tests/annulet_sync.rs` (c) | A joiner's first body asks are lost, and bodies then arrive backwards with the frontier withheld. It re-asks after `BODY_REQUEST_TIMEOUT_MS` and converges to the tip. |

**The compose (not yet brought up):** `qumbra-deploy` `compose/docker-compose.annulet-devnet.yml`. First build the lab image from this repo:

```sh
docker build -f deploy/docker/Dockerfile --target runtime -t qumbra-lab:annulet-devnet .
```

`init` then writes the genesis and the dev sequencer key. The sequencer and the two followers run `qumbra-node run`, and the faucet runs `qumbra-faucet annulet`. The published ports are all loopback: followers' discovery on 9421 and 9422, the faucet on 8090. **Memory:** an S grant peaks at about 7 GB and a P send at about 15 GB, and the faucet container needs that headroom.

## What it proves

- The node's own code (`RunningNode`, over real TCP) runs an Annulet net with the L2 verifier as its default: sealed blocks, final on acceptance, and followers applying them under the same verifier.
- A fee-unit faucet can grant from genesis stock with exact-tariff notes, and does not re-grant after a restart.
- A policy-asset (`USDT-test`, Hybrid) transfer, shape P with vPublic = 0, is built from **served** witnesses (commitment tree, registry openings), proved, submitted over HTTP and accepted by three nodes.
- A recipient who knows only its KEM key finds its notes from a follower's served surfaces and can spend them.
- Sealed-header catch-up works across full batches under the limiter, and lost or reordered bodies converge.

## What it does not prove

- **That the compose runs.** It has only been parsed (`docker compose config`). The first bring-up is a scheduled later step.
- **A user wallet.** The spend assembly (`qumbra_faucet::annulet`) is the wallet side of an L2 spend, built here because the faucet needs it first. C2 promotes it into the wallet. No user wallet derives an L2-spendable `rkm` = `H(nk ‖ D ‖ d)` yet (C1), so the faucet's HTTP grant is only useful to a client that does.
- **Issuer operations.** Mint, redeem, freeze, allowlist and a non-zero vPublic are C3's. The freeze tree here is empty and never updated.
- **Runtime registry changes.** The registry is genesis-only until A2.
- **An explorer or attestation page.** Those are D1's.
- **Abuse resistance.** The faucet has no tickets and no rate limit, and 16 requests exhaust it.
- **The lane is provisional** (`L2_CFG_PROVISIONAL`, A1). Nothing here freezes it.
- **Out-of-order bodies cost a re-ask interval.** A sealed body whose parent is not yet applied is not held for later on an Annulet node: it is dropped as an orphan and fetched again after `BODY_REQUEST_TIMEOUT_MS`. Test (c) shows that this converges, but not that it is fast.
- **Phase 0 is what it is.** From l2-own-circuit-decision §4, verbatim:

  > Under Phase 0 option (a) — no QMB on L2 — a stablecoin pilot is honestly **a sidechain that
  > reads L1 anchors**: its value to Qumbra is the shared toolchain, the shared wallet, the
  > attestation surfaces, and the path to Phase 1; it is not yet Qumbra's money. The doc says so
  > because the pilot's press copy will be tempted not to.

## Deferred, with reasons

- **The binary telemetry form tail goes to D1.** No Annulet `/v1/telemetry` consumer ships in B6 (the explorer and opview are D1's). The text surfaces already name the form (`form=annulet finality=operator`, B2), and a fleet-visible `RPC_VERSION` bump should arrive with the milestone that can use it. The #212 recipe travels with it.
