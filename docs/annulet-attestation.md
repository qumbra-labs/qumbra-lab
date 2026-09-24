# Annulet attestation and registry — the explorer's L2 surfaces (L2-D1)

> [中文版](annulet-attestation-zh.md) · lab issue #726 · crates: `qlab-node` (`asset_supply`), `qumbra-explorer` (`attest`), `qumbra-node` (`audit-supply-l2`)

**What it is.** On an Annulet (L2) chain, the explorer serves two JSON documents from its own keyless follower node:

- `GET /v1/attest` — the per-asset **attestation**:
  - **genesis rows**: each asset's genesis issuance, recomputed from the genesis file's public plaintext notes, each commitment checked;
  - **asset rows**: Σ minted, Σ redeemed and outstanding from the public `vPublic` terms of every main-chain block body;
  - **flow rows**: those terms per height;
  - whether the node's own supply state agrees. Every disagreement is named, never reconciled.
- `GET /v1/assets` — the **registry**: every registered asset's leaf (mode, issuer key, freeze and allow roots, flags) and the registry root. Registry leaves are public by design.

On an L1 chain both routes answer `"available": false` and carry no figures. The health document's `supply` block on an Annulet chain says there is no emission on the L2 and points at `/v1/attest`.

**What it attests — and what it does not.**
- **Issuance integrity recomputed from public block bodies.** Every counted unit was minted by a `vPublic` term the issuer's proof authorized, or issued in the genesis file.
- **Not a consensus commitment.** No Annulet header carries a supply figure at Phase 0; a `supply_cmt` chain is a named follow-up.
- **Issuance ≠ reserves.** Nothing here says what backs the asset.
- **Aggregates only.** No balances, no holders, no transfer graph, no transaction lookup.

**Replay it yourself.** The explorer's figures and the node's supply state are the same code on the same data, so the independent check is to recompute from a data dir you hold:

```
qumbra-node audit-supply-l2 --data-dir <dir> --genesis <annulet-genesis> [--claimed <attest.json>]
```

- Without `--claimed` it prints the figures (`GENESIS …`, `ASSET …`).
- With `--claimed` it reads a served `/v1/attest` document and names every row that does not reproduce: `DIVERGENT asset 7: …`, `DIVERGENT flow height=2 asset=7: …`, `DIVERGENT genesis asset 0: …`.
- Exit codes: **0** reproduces, **1** does not, **2** cannot run.

**Known gap (named follow-up, B3b).** The node's outstanding figure counts `vPublic` flows only. It does not yet seed genesis issuance, so a redeem of a genesis-minted note is refused as a supply underflow. That is why the document carries genesis rows *beside* the flow totals, with a note saying so. When B3b seeds the node's supply from genesis, the two agree and the note goes.
