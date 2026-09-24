# Annulet attestation and registry — the explorer's L2 surfaces (L2-D1)

> [中文版](annulet-attestation-zh.md) · lab issue #726 · crates: `qlab-node` (`asset_supply`), `qumbra-explorer` (`attest`), `qumbra-node` (`audit-supply-l2`)

**What it is.** On an Annulet (L2) chain, the explorer serves two JSON documents from its own keyless follower node:

- `GET /v1/attest` — the per-asset **attestation**:
  - **genesis rows**: each asset's genesis issuance, recomputed from the genesis file's public plaintext notes, each commitment checked;
  - **asset rows**: Σ minted and Σ redeemed from the public `vPublic` terms of every main-chain block body, and outstanding = genesis issuance + minted − redeemed — one row per asset issued at genesis or by a flow;
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

**Genesis supply counts (B3b, lab #728; document version 2).** The node's outstanding figure starts from each asset's genesis issuance, so a redeem of genesis supply is not an underflow and a redeem past genesis + minted is. The document's `outstanding` is the same figure. Version 1 (L2-D1) counted `vPublic` flows only and said so in its `genesis_note`; the audit tool refuses to compare a version-1 document against a version-2 recomputation, by name.
