# L2-E1 —— pUSD-test 稳定币试点,在 devnet 测试台上跑通

[English](annulet-pilot-2026-09-25.md)

本文由 `scripts/annulet-pilot-render.py` 从 Graviton 车道运行 **36147094057**(`78e91da0d770e95a6d36bfa4ab786cb2e070d5f3`)的 `pilot-evidence` 产物生成。以下没有一处手写,数字都是测试自己记下的。

## 0. 这个试点是什么,不是什么

按 `l2-own-circuit-decision` §4,Phase-0 稳定币试点是**一条读取 L1 锚点的侧链**。它跑在 `qumbra-node` 的 Annulet 分叉上:单一排序器、L2 电路族、注册表;没有跨链桥,L2 上也没有 QMB。它对 Qumbra 的价值在于共用的工具链、钱包和证明面,以及通往 Phase 1 的路径。**它还不是 Qumbra 的钱。**在这个测试台里,L1 锚点字段固定在创世里,不读取任何在线的 L1。

## 1. 试点资产

`pUSD-test`("Pilot USD (test)",资产编号 21)是**测试**资产:发行方和冻结令都是**模拟的**,不代表任何真实的发行方、监管方或货币。模式 Hybrid,冻结由 `issuer update` 在运行时发布,赎回关闭(持有人把币转给发行方,由发行方销毁)。三个进程内节点,用真实的 `L2Verifier`;参与方是发行方 I 和持有人 A、B、F(F 在第 8 步被冻结)。

## 2. 各步骤 —— 证明出的流通量

每一步之后,测试在三个节点上都断言:`/v1/attest`(浏览器自己的代码)报告 `node_agrees = true`,且证明出的流通量同时等于节点的供应账本和预期值。

| 步骤 | 内容 | 等价命令 | 高度 | nullifier 数 | 证明值(n0 / n1 / n2) | 预期 | 耗时 s |
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

## 3. 交易

DA 字节即 Annulet 线上编码(含证明、发现载荷和 L2 面)。**verify ms 是在测试进程里测的**:对每笔已上链交易用 `L2Verifier` 重验一遍,不是排序器的准入路径。

| 步骤 | 形状 | 高度 | 交易 id | nullifier 数 | 手续费 | 证明 B | 发现 B | DA(线上)B | verify ms(测试进程) |
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

## 4. 第 9 步 —— 被冻结的持有人两次被拒

钱包在生成证明之前就拒绝了 F 的转账:`Frozen`。

F 用冻结前的叶子手工伪造的花费能生成证明,但节点拒绝了它:

```
refused: l2-surface L2RegistryRootStale { index: 0 }
```

## 5. 最终账目

| 持有人 | 持有量 |
|---|---|
| A | 50 |
| B | 400 |
| F(已冻结) | 150 |
| 发行方 I | 0 |
| **流通量** | 600 |

铸造 750 − 赎回 150 = 600;F 的 150 被冻结,但仍计入流通量。

## 6. 耗时

R 的证明加提交时间,在钱包命令外围计时(两者都不等上链):注册 **13.9 s**,冻结 **13.9 s**。每步耗时见步骤表(证明、提交和等待上链合计)。同一产物里的 `pilot.log` 是任务的带时间戳控制台,有同样的行和挂钟时间。

---

`scripts/annulet-pilot-render.py --jsonl pilot.jsonl --run-id 36147094057 --sha 78e91da0d770e95a6d36bfa4ab786cb2e070d5f3 --date 2026-09-25`
