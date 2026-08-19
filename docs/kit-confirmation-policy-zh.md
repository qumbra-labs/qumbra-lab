# 交易所工具包——确认策略:已最终确定 = 可入账(lab #483 阶段 3)

> [English](kit-confirmation-policy.md)

**状态:交易所/VASP 工具包的阶段 3 交付物
([#483](https://github.com/qumbra-labs/qumbra-lab/issues/483);规范:
`qumbra-design/ecosystem-and-adoption.md` §4、`consensus-and-network.md` §4–§6)。**
读者:决定一笔 QMB 充值何时可以安全入账的交易所对接与风控团队。配套文档为
工具包 README(`crates/qlab-vask/README.md`)与托管审计文档
(`docs/kit-custody-audit.md`)。技术细节以英文版为准;行号基于 lab `main`
`cf15b11`。

---

## 1. 规则

**当且仅当充值所在区块高度 ≤ 链的已最终确定(finalized)头时入账。除此之外
一概不用——不数确认数、不用深度启发式、不做"应该够深了"的判断。**

Qumbra 是混合链:无许可 PoW 出块,BFT 最终性委员会对区块做检查点
(Crosslink 形态,基于 Ebb-and-Flow;`consensus-and-network.md` §4)。已
最终确定的区块不可逆——共识拒绝任何会重组(reorg)到已最终确定检查点之前
的分叉,而且链上交易本身只锚定已最终确定的承诺根
(`consensus-and-network.md` §6),协议自己就拒绝在未最终确定的状态上构建
价值。按最终性入账的交易所直接继承这一保证;数确认数的交易所是在手工重新
推导它的弱化版本。

这是本设计对其他链"深度竞赛"的回答:ETC 在遭受 51% 攻击后,交易所把确认
数提高到 >12,000(约两周)(`ecosystem-and-adoption.md` §4 的引文)。针对
Qumbra 的租算力双花,在充值背后第一个已最终确定的检查点处就死掉了——贴着
链头的骚扰(griefing)仍然可能但无利可图;重组到最终性之前不是成本问题,
而是被每个诚实节点直接拒绝。

## 2. 这里的"已最终确定"在机制上是什么

以下委员会机制全部为 lab 真实实现并运行在内部 T0 网上;下表常量为
**devnet 钉定、测试网可调、并未冻结(NOT frozen)**——每一项都带来源,改
动可见;它们的变化只影响 §1 规则的延迟,不影响规则本身。

| 事实 | 当前取值 | 依据 |
|---|---|---|
| 出块 | PoW,目标 75 s | 已决定(B2),`qumbra-design/consensus-parameters.md` §2 |
| 委员会 | 21 把 ML-DSA-65 密钥(genesis 内置) | 设计范围 N≈20–50,params §4;devnet genesis committee₀ |
| 法定人数 | ⌊2N/3⌋+1 → **21 取 15** | `qlab-devnet/src/committee.rs:85` |
| 检查点节奏 | 每 **8 个区块**(按目标约 10 分钟) | `qlab-devnet/src/params_devnet.rs:94`,标注 `[full-M8]`,未冻结 |
| 签名滞回 | 仅当链头 ≥ 槽位+**2** 才签该槽 | `params_devnet.rs:106`(issue #269) |
| 降级模式阈值 | 链头 − 已最终确定 > 16 块 | `params_devnet.rs:149` |

检查点落在节奏网格上——genesis 作为引导行为豁免,之后是高度 8、16、24、…
的槽位。一个槽位要等链头越过两块滞回才会被签(2026-08-05 的事故中,顶着链
头竞态签名连烧了三个槽位;#269 即修复),并在 21 把密钥中有 15 把签署同一
检查点变体时最终确定。**没有任何单一节点持有法定人数**——交易所读到的最
终性是一个分布式事实,已在横跨三大洲的 WAN 上连续 48 小时零回退地演示过
(`docs/m10-t03-phase-b-wan-run.md`)。

## 3. 对接方怎么读它

入账参考实现(`qumbra-credit-ref`)端到端实现了这条规则;自研流程的交易所
需要的读取恰好是这些:

- 对节点 discovery 端点 **`GET /v1/anchors`**
  (`qumbra-node/src/discovery_server.rs:191`),解码为 `AnchorSet`
  (`qlab-node/src/rpc.rs:1113`):`tip_height`,以及作为 **`Option`** 的
  `finalized_height`——`None` 表示链上还没有任何最终确定,任何东西都不可
  入账。参考实现刻意扫描到*链头*而只入账到*已最终确定*,让"你的充值在链
  上但还没最终确定"和"查无此充值"保持为两个可区分的答案。
- **当且仅当 `deposit_height ≤ finalized_height` 时入账**,每笔充值一次,
  以充值的已承诺 commitment `cm` 为键
  (`qumbra-credit-ref/src/lib.rs:247` `try_credit`;只入账一次的集合与两
  个最终性拒绝是 `lib.rs:116` 的 `Refusal` 变体)。
- **两种等待状态是命名的 409,不是错误**:`nothing-finalized` 与
  `not-finalized {deposit_height, finalized}`——客户端等最终性到达该充值
  后重试;这不是对充值本身的否定判断。状态码由测试锁定
  (`lib.rs:169` `http_status`)。

整个转换过程在真实最终性机制上有端到端演示:
`qumbra-credit-ref/tests/credit_e2e.rs:175`
(`a_deposit_credits_once_after_finality_and_every_refusal_names_itself`,
(f) 段):挖在已最终确定头之上的充值先拒绝 `not-finalized`,节奏网格上落下
一个检查点后,同一信封随即入账——且只入账一次。

只做监控不做对接的运维方:`/v1/telemetry` 上的 `final=`/`fid` 同时说出最终
确定到多高**以及是什么**(`qlab-node/src/telemetry.rs:26`——两个节点可能
高度一致而身份不一致,这才是值得报警的失败),`dfin` 是重启后仍存续的持久
头(`telemetry.rs:55`)。`qumbra-opview` 就是为跨节点比对这些而存在的。

## 4. 充值台应预期的延迟

这是由钉定常量推出的算术,不是测量值:高度 `h` 的充值等第一个节奏槽位
`S ≥ h`(0–7 块),加 2 块滞回,加投票聚合。按 75 s 目标即从挖出到可入账
**约 2.5 到约 11.5 分钟**;对照 WAN 实测出块间隔(1,707 个间隔均值 86 s,
普通 PoW 方差——`docs/m10-t03-phase-b-wan-run.md`),实际包络再宽几分钟。
投票聚合本身是秒级,不是主导项;节奏才是。如果上币谈判需要更短的数字,诚
实的旋钮是节奏常量(测试网可调,§2),不是交易所侧的深度启发式。

提币处理同理反向适用:出账交易以其区块最终确定为结算,不以挖出为结算。

## 5. 失败模式,以及本策略往哪个方向失败

**委员会停摆。** Ebb-and-Flow 的刻意降级:委员会失去法定人数时,PoW 继续
出块但已最终确定头冻结(滞后超过 16 块进入降级模式,
`params_devnet.rs:149`)。在本策略下,充值此时**在 `not-finalized` 处排队,
而不是入账**——失败方向是延迟,绝不是错误入账一笔可被重组的充值。停摆期
间不要退回数深度:停摆恰恰是链退回到只有概率性保护的时刻,也就是深度最不
值钱的时刻。T0 网在这里交过真实学费——2026-08-05 的 51 分钟最终性中断
(`docs/incident-2026-08-05-finality-night.md`)与 2026-08-12 的停机边界停
摆——两次出块都未中断、已最终确定的内容零回退,只按最终性入账的充值台不
会错账,只会晚一点。

**节点分歧。** 单一上游节点只有在与委员会分歧时才可能对*什么*已最终确定
出错——§3 的 `fid` 身份检查就是它的报警;交易所跑两个上游节点、在两者
`fid` 不一致时拒绝入账,用一台额外节点的成本换来交叉校验。

**本策略不覆盖的**:充值的*内容*(那是披露信封的职责——工具包 README 的
"流程"一节),以及交易所对已收资金的自身托管
(`docs/kit-custody-audit.md`)。
