# L2-E1 — the pUSD-test stablecoin pilot, run on the devnet harness

[中文版](annulet-pilot-2026-09-25-zh.md)

Rendered by `scripts/annulet-pilot-render.py` from the `pilot-evidence` artifact of Graviton-lane run **36147094057** at `78e91da0d770e95a6d36bfa4ab786cb2e070d5f3`. Nothing below is hand-written; numbers are the test's own record.

## 0. What this pilot is, and what it isn't

Per `l2-own-circuit-decision` §4, a Phase-0 stablecoin pilot is **a sidechain that reads L1 anchors**. It runs on the Annulet fork of `qumbra-node`: a single sequencer, the L2 circuit family, the registry, and no bridge and no QMB on L2. Its value to Qumbra is the shared toolchain, wallet and attestation surfaces, and the path to Phase 1. **It is not yet Qumbra's money.** In this harness the L1 anchor fields are genesis-static; no live L1 is read.

## 1. The instrument

`pUSD-test` ("Pilot USD (test)", asset id 21) is a **test** instrument: the issuer and the freeze order are **simulated**, and no real issuer, regulator or currency is represented. Mode Hybrid, runtime freeze by `issuer update`, redeem closed (holders redeem by sending to the issuer, who burns). Three in-process nodes under the real `L2Verifier`; participants are the issuer I and holders A, B and F (F is frozen at step 8).

## 2. Steps — attested outstanding supply

After every step the test asserts, on all three nodes, that `/v1/attest` (the explorer's own code) reports `node_agrees = true` and that the attested outstanding supply equals both the node's supply ledger and the expected figure.

| step | what | equivalent command | height | nullifiers | attested (n0 / n1 / n2) | expected | wall s |
|---|---|---|---|---|---|---|---|
| 0 | genesis | `(genesis: asset 0 only)` | 0 | 0 | 0 / 0 / 0 | 0 | 0.0 |
| 1 | register pUSD-test (Hybrid, redeem closed) | `qumbra-wallet issuer register --asset 21 --mode hybrid --net annulet` | 1 | 1 | 0 / 0 / 0 | 0 | 14.0 |
| 2 | mint 200 → A | `qumbra-wallet issuer mint --asset 21 --amount 200 --to <A> --net annulet` | 3 | 4 | 200 / 200 / 200 | 200 | 58.8 |
| 3 | mint 200 → A | `qumbra-wallet issuer mint --asset 21 --amount 200 --to <A> --net annulet` | 5 | 7 | 400 / 400 / 400 | 400 | 59.2 |
| 4 | mint 200 → A | `qumbra-wallet issuer mint --asset 21 --amount 200 --to <A> --net annulet` | 7 | 10 | 600 / 600 / 600 | 600 | 59.0 |
| 5 | mint 150 → F | `qumbra-wallet issuer mint --asset 21 --amount 150 --to <F> --net annulet` | 9 | 13 | 750 / 750 / 750 | 750 | 58.7 |
| 6 | A pays B 500 (merge 200+200, then pay 400+200) | `qumbra-wallet send --net annulet --asset 21 --amount 500 --to <B>` | 13 | 19 | 750 / 750 / 750 | 750 | 118.0 |
| 7 | B pays A 100 (fee-split, then pay) | `qumbra-wallet send --net annulet --asset 21 --amount 100 --to <A>` | 16 | 25 | 750 / 750 / 750 | 750 | 86.3 |
| 8 | freeze F (simulated order) | `qumbra-wallet issuer freeze --asset 21 --add <F> --net annulet` | 17 | 26 | 750 / 750 / 750 | 750 | 14.1 |
| 9 | F refused (wallet: Frozen before proving; node: stale-leaf spend refused) | `qumbra-wallet send --net annulet --asset 21 --amount 50 --to <A> --freeze-list <published>` | 18 | 26 | 750 / 750 / 750 | 750 | 62.4 |
| 10 | A sends 150 to the issuer (redeem request) | `qumbra-wallet send --net annulet --asset 21 --amount 150 --to <issuer> --freeze-list <published>` | 20 | 29 | 750 / 750 / 750 | 750 | 60.3 |
| 11 | the issuer redeems 150 | `qumbra-wallet issuer redeem --asset 21 --amount 150 --freeze-list <published> --net annulet` | 22 | 32 | 600 / 600 / 600 | 600 | 58.7 |

## 3. Transactions

DA bytes are the encoded Annulet wire (proof, discovery payload and L2 surface included). **verify ms is measured in the test process** by re-verifying each sealed transaction with `L2Verifier` — not the sequencer's admission path.

| step | shape | height | tx id | nullifiers | fee | proof B | discovery B | DA (wire) B | verify ms (test process) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | R | 1 | `5b720c371d768be1…` | 1 | 4 | 348,013 | 2,517 | 350,861 | 10.63 |
| 2 | P | 3 | `042e9093aa265852…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.28 |
| 3 | P | 5 | `55c70e26487a7247…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.21 |
| 4 | P | 7 | `6b37ed778b1db8f9…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.10 |
| 5 | P | 9 | `bd266ddefb9dbdac…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.19 |
| 6 | P | 11 | `5520a25efdf0071a…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.43 |
| 6 | P | 13 | `abde6c24b2ebc04c…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.33 |
| 7 | S | 14 | `64faceed544a3a47…` | 3 | 1 | 359,121 | 2,517 | 361,880 | 11.39 |
| 7 | P | 16 | `5d77cc8177e2ee71…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.08 |
| 8 | R | 17 | `32a469971a85cbc2…` | 1 | 4 | 348,013 | 2,517 | 350,861 | 10.63 |
| 10 | P | 20 | `d8ec5d2502cd288b…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.46 |
| 11 | P | 22 | `3ad54d51d864f33d…` | 3 | 2 | 391,652 | 2,517 | 394,433 | 12.19 |

## 4. Step 9 — the frozen holder is refused twice

The wallet refused F's send before proving: `Frozen`.

F's hand-forged spend under the pre-freeze leaf proved, and the node refused it:

```
refused: l2-surface L2RegistryRootStale { index: 0 }
```

## 5. Final ledger

| holder | held |
|---|---|
| A | 50 |
| B | 400 |
| F (frozen) | 150 |
| issuer I | 0 |
| **outstanding** | 600 |

Minted 750 − redeemed 150 = 600; F's 150 is frozen but still outstanding.

## 6. Timings

R prove + submit, measured around the wallet verb (neither waits for inclusion): register **13.9 s**, freeze **13.9 s**. Per-step wall time is in the steps table (proves, submits and settle waits together). The job's stamped console (`pilot.log` in the same artifact) carries the same lines with wall-clock stamps.

---

`scripts/annulet-pilot-render.py --jsonl pilot.jsonl --run-id 36147094057 --sha 78e91da0d770e95a6d36bfa4ab786cb2e070d5f3 --date 2026-09-25`
