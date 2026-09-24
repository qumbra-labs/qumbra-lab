# Annulet 发行证明与注册表：explorer 的 L2 接口（L2-D1）

> [English](annulet-attestation.md)（技术细节以英文版为准）· lab issue #726 · 涉及 crate：`qlab-node`（`asset_supply`）、`qumbra-explorer`（`attest`）、`qumbra-node`（`audit-supply-l2`）

**是什么。** 在 Annulet（L2）链上，explorer 用它自己那个不持有任何私钥的跟随节点，对外提供两份 JSON 文档：

- `GET /v1/attest` —— 按资产的**发行证明**：
  - **genesis 行**：每个资产在 genesis 里的发行量，从 genesis 文件中公开的明文 note 重新算出，每条都核对承诺；
  - **资产行**：主链上每个区块体里公开的 `vPublic` 条目，合计出累计发行、累计赎回和流通量；
  - **流水行**：这些条目按高度逐条列出；
  - 节点自己的供应量状态是否一致。每一处不一致都点名列出，从不私下抹平。
- `GET /v1/assets` —— **注册表**：每个已注册资产的叶子（模式、发行方密钥、冻结根和白名单根、标志位）以及注册表根。注册表叶子按设计就是公开的。

在 L1 链上，这两个接口都返回 `"available": false`，不带任何数字。Annulet 链的健康文档里，`supply` 一栏会说明 L2 没有出块奖励，并指向 `/v1/attest`。

**它证明什么，不证明什么。**
- **按公开区块体重算的发行完整性。** 计入的每一单位，要么由发行方证明授权的 `vPublic` 条目铸出，要么在 genesis 文件里发行。
- **不是共识层承诺。** 第 0 阶段的 Annulet 区块头不带任何供应量数字；`supply_cmt` 承诺链列为后续事项。
- **发行 ≠ 储备。** 这里不说明资产背后有什么资产支撑。
- **只有汇总数字。** 没有余额、没有持有人、没有转账图谱，也不能按交易查询。

**自己复算。** explorer 的数字和节点的供应量状态是同一段代码跑在同一份数据上，所以真正独立的核对办法，是拿你自己手里的数据目录重新算一遍：

```
qumbra-node audit-supply-l2 --data-dir <dir> --genesis <annulet-genesis> [--claimed <attest.json>]
```

- 不带 `--claimed` 时只打印数字（`GENESIS …`、`ASSET …`）。
- 带 `--claimed` 时，读入一份 `/v1/attest` 返回的文档，逐条点名对不上的行：`DIVERGENT asset 7: …`、`DIVERGENT flow height=2 asset=7: …`、`DIVERGENT genesis asset 0: …`。
- 退出码：**0** 能复现，**1** 不能复现，**2** 无法运行。

**已知缺口（已列为后续事项，B3b）。** 节点的流通量只计 `vPublic` 流水，还没有把 genesis 发行量计入起点，所以赎回一张 genesis 时铸出的 note，会被当作供应量不足而拒绝。这就是为什么文档把 genesis 行放在流水合计*旁边*、并附一句说明。等 B3b 让节点的供应量从 genesis 起算，两边就会一致，这句说明也就可以去掉。
