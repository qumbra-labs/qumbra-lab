# 远程证明 —— 候选 A 对 B 的推荐

**状态:已记录的推荐,不是 Larry 批准,不是 implementation approval。** 本文回答
[`remote-proving-decision-zh.md`](remote-proving-decision-zh.md) 留下的 A-or-B
问题。它不取代那份记录。Authorization primitive、confidential-compute 目标与 §8
上线门槛仍未实测。任何候选通过那些门槛之前,公网 prover 都不得承载真实价值。
英文权威版:[`remote-proving-a-vs-b.md`](remote-proving-a-vs-b.md)。

写于 2026-08-23,接续 PR #620。

本文不会悄悄修改 Qumbra 的 binding design spec。如果最终走 protocol-level
authorization,实现前必须给当前"每笔交易一个 monolithic STARK;没有 per-spend
signature"决策做一份带日期的 design-repo 修正,然后才能改 lab circuit 或 wire。

---

## 1. 一句话结论

**A 是承重的 launch basis**(共识绑定、worker 无法伪造的手机持有授权)。**B 是
Qumbra 运营的默认 send 路径上必须有的隐私层**,不是 A 的替代品。真实价值的公网
proving 只有两道门槛都过才上线:A 管盗币,B 管 witness 可见性。

如果父记录 §3 必须只标一格:**A**。

---

## 2. 本文在回答什么

父记录已经定下产品约束并点名两个候选,但没有选型。诚实的矩阵是:

| | 不能盗币 | 不能看见/关联 witness | T2 / 共识 |
|---|---|---|---|
| **A** —— 手机持有 authorization | 可以,前提是共识绑定手机批准的完整 intent | 普通 worker 下**失败** | re-mint 级协议变更 |
| **B** —— attested confidential worker | 只有接受 TEE / image / isolation 假设才通过 | 可减少 payload 可见性;ingress metadata 仍在 | 原则上不需 protocol re-mint |

Larry 已经裁定:所有支持的手机都必须能 send;用户的 Mac、家用服务器或租用 VM
不能成为常驻 send 路径。因此共享服务是手机的**默认** send 路径,不是可选的
power-user fallback。这一事实同时压在两列上:默认路径上的盗币不合格,默认路径
上的 viewing oracle 也不合格。

产品比较不是"b4 对相信 Qumbra",也不是把 A 和 B 当成互斥的完整产品。

---

## 3. 为什么承重的是 A

Qumbra 的 binding design 是密码学,不是硬件信任:

- whitepaper 与
  [`transaction-model-and-anonymity-set.md`](https://github.com/qumbra-labs/qumbra-design/blob/main/transaction-model-and-anonymity-set.md)
  把花费授权放在**一个** monolithic STARK **内部**,没有 trusted setup,共识路径
  只用保守 Keccak
- "没有 per-spend signatures"成立,是因为**钱包自己证明交易**,签名相对电路里的
  `sk` 知识是多余的
- 这个前提已经死了:手机扛不住 b16(M2 ladder 上约 15 GB peak RSS),Larry 也排除了
  用户运营常驻 prover
- PR #618:拿着 `WitnessBundle` 的委托 prover 就拿着 selected-input 的花费权

A 才是新产品真正需要的 design-repo 修正。B 靠把花费安全挪到 SEV-SNP / TDX /
firmware / cloud / side-channel 假设上,来保住今天的 wire——而这正是 Qumbra 在
别处一律拒绝的额外信任。

无法廉价回补的不对称决定顺序:

| 先落地 | 以后再加另一个 |
|---|---|
| **先 A** | B 是 transport / trust-boundary 升级;不必第二次 re-mint |
| **先 B** | A 仍然需要 T2 re-mint、AIR / wire / genesis,以及带日期的 design-spec 修正 |

A 没法便宜补进去。B 可以。所以 A 是协议目的地;B 是基础设施。

现稿 Hash-OTS **不是** A。保留结构接缝:把 authorization-key-tree root 写进
`rkm`,STARK 只证明 32-byte leaf,node 原生验签。现稿 WOTS+ 在父记录 §6 的 P0
关闭前丢掉(state rollback / key reuse、实例不完整、dummy-slot 规则)。
Authorization spike 应以标准化 **stateless** leaf(先 ML-DSA)为默认 A
primitive,除非实测 WOTS+ 在 rollback 安全性上胜过它。

---

## 4. 为什么单靠 A 不是隐私产品

父记录矩阵写得很清楚:普通 worker 下 A 在 `cannot see/link` 上**失败**。
[`hash-ots-spend-authorization-zh.md`](hash-ots-spend-authorization-zh.md)
也写明 `nk` 是 full-viewing-class 材料。

默认手机路径 + 只有 A,意味着 Qumbra 运营的服务对每一笔远程 send 都能看见:

- selected inputs、nullifiers、金额、收款与找零
- `nk`(full-viewing-class)
- device identity、IP、timing,以及随后上链的交易

这是一台 viewing oracle,坐在大多数手机会走的唯一 send 路径上。只有防盗、没有
隐私,不是这条链的产品。

B 是当前唯一能保留今天共识、同时不让普通 operator 读到 witness 明文的路线。
Ingress metadata 可关联性两条路都还在,需要单独的上线审查。

---

## 5. 为什么单靠 B 不是盗币模型

B 的"不能盗币"只有在 attestation、image pin、isolation、debug-disabled,以及
TEE / cloud / firmware 故事全部成立时才成立。一次破裂同时给出**盗币和完整
witness**。这不是 Qumbra 能对外说的 non-custodial。

当前表格里的 B 也还不能当产品选项。成为选项之前,精确 SEV-SNP/TDX 级目标必须
证明:

1. 当前 12–15 GB 级 b16 job 的 peak private memory、cold/warm time、proof
   bytes、failure behavior 与成本
2. iOS/Android 都能验证 fresh、correct、non-debug、non-revoked attestation,
   并覆盖 negatives
3. bundle 在 ingress、queue、host、snapshot、swap、crash collection 与
   operator observability 全程加密
4. rollback、replay、cancellation、teardown 与 regional outage 行为
5. 明写 hardware、firmware、cloud、side-channel 与 availability trust

STARK proving 对 TEE 是敌对负载:巨大的结构化 LDE、可预测的内存流量、长运行。
Side-channel 与 memory-encryption 税不是文书工作。必须实测。

B 的用途:(1) 在现行共识上做无价值的 service-mechanics experiment,父记录已经
允许;(2) A 存在之后隐藏 payload。不是长期 cannot-steal 声明。

---

## 6. "两者都要"在操作上是什么意思

| 层 | 职责 | 省略时的失败模式 |
|---|---|---|
| **A**(共识) | worker 无法授权手机没批准的 outputs 或 semantic fields | TEE / operator / image 漏洞花掉 selected notes |
| **B**(传输) | 普通 ingress、queue、host 与 operator 只看见 ciphertext | 默认 send 路径变成 viewing oracle |
| **A 和 B 都没有** | trusted `WitnessBundle` | 真实价值场景已被排除 |
| **只有 A** | 不能盗,能看见 | 默认路径上隐私产品是假的 |
| **只有 B** | *如果* TEE 成立,operator 读不到 | 盗币模型永远绑在 Intel/AMD/cloud 上 |

Ingress 仍可把 device identity、IP、timing 与随后的交易拼在一起。这是第三道
门槛。它不选 A 或 B;它约束服务怎么暴露。

---

## 7. 本文没有决定的事

父记录的工作顺序仍然要跑。本文不跳过:

0. 独立加固:把 paired-prover 两边的 128 MiB protocol ceilings 换成实测
   bundle/artifact ceilings。
1. Authorization spike:端到端规定并比较标准 WOTS+、标准 stateless signature
   leaf 与 random-index WOTS+ leaf,覆盖 dummy semantics 与
   rollback/multi-device。
2. Confidential-worker lane:在精确目标 instance 上跑今天的 b16 电路,并完成
   mobile attestation negatives。
3. 然后锁定 launch basis。这里的推荐是 **A,外加 B 作为 overlay**。不得按估算
   行锁定成本、wire bytes 或 TEE fit。
4. 如果 spike 之后 A 仍是协议目的地:先给 design repo 做带日期的修正,再改 lab
   circuit 或 wire。
5. 完成以上步骤后才实现并 pilot 公共 service boundary。

本文没有构建 backend、circuit、`CONSENSUS_CFG`、genesis、cloud resource 或
deployment。

---

## 8. 相对父记录该怎么读

- [`remote-proving-decision-zh.md`](remote-proving-decision-zh.md) 仍是已决约束
  与上线门槛的权威入口。在 Larry 批准这份推荐之前,那份记录的"路线未选"仍然
  成立。
- [`backend-assisted-proving-security-zh.md`](backend-assisted-proving-security-zh.md)
  仍是 threat-model 与拓扑证据。
- [`hash-ots-spend-authorization-zh.md`](hash-ots-spend-authorization-zh.md) 仍是
  研究候选。这里用它的 `rkm` root-binding insight;不用它的 WOTS+ safety
  claim。
- [`phone-self-proving-reopened-zh.md`](phone-self-proving-reopened-zh.md) 与
  [`m2-iphone-plan.md`](m2-iphone-plan.md) 仍是默认路径是远程证明、而不是人人
  b4 的原因。

如果这份推荐与父记录在已决约束上冲突,父记录赢。如果在 A-versus-B 上冲突,在
父记录被带日期的修正更新之前,本文是已记录的推荐。
