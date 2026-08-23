# 远程证明 —— 候选裁定:A 是上线安全基础,B 是之后叠加的一层

**状态:2026-08-23 已裁定。Larry 在产生这份建议的同一次会话里接受了 reviewer-f5 的建议。
本裁定选定的是 [`remote-proving-decision.md`](remote-proving-decision.md) §9.3 所说的
*上线安全基础*。它不批准实现,不选定签名原语,也不修改绑定性设计规范 —— 这些仍按那份
记录的门槛执行。**
英文权威版:[`remote-proving-candidate-ruling.md`](remote-proving-candidate-ruling.md)。

---

## 1. 裁定

**候选 A —— 共识绑定的手机持有授权 —— 是带真实价值的共享 prover 上线时的安全基础。
候选 B —— attested confidential worker —— 是之后叠加在 A 之上的部署层隐私加强,不是
上线前提。**

两者不是同一层的备选项;决策记录里"A 或 B 或两者"的提法,应读作已收敛为
**先 A,后 B**。

## 2. 理由 —— 按决定性排序

### 2.1 两个候选只能朝一个方向叠加

A 改的是**协议**:节点拒绝任何缺少手机对完整 intent 授权的交易。它的保证是任何人都能从链上
验证的数学性质。

B 改的是**部署**:worker 跑在 SEV-SNP/TDX 一类的机密虚拟机里。它的保证是一串假设 ——
CPU 厂商固件、云运营方、attestation 服务、已度量的镜像,以及不存在可利用的侧信道。

已经有 A 的链,加 B 不碰共识。以 B 上线的部署,再加 A 得 re-mint 或硬分叉。
先 A 是唯一不会堵死另一条路的顺序。

### 2.2 re-mint 窗口只对 A 开着,对 B 无关

T2 已 mint 未 launch。今天 A 的共识改动是一个 PR 加一次走现有流程的 re-mint。launch 之后
就是两边都有真实价值的硬分叉。B 永远不需要这个窗口。窗口会自己关上;等待只伤害 A。

### 2.3 只靠 B 上线,与链自己的信任论点自相矛盾

Qumbra 的设计押注是共识里处处用保守哈希加 STARK,连格签名都以工程保守为由拒绝。如果把
对用户最要紧的那个问题 —— *谁能花我的钱* —— 建立在 TEE attestation 上,就等于把整个
系统里最弱的信任假设放在最敏感的位置。SGX 和 SEV 被攻破的公开记录已经长到,"attestation
成立"不是一条隐私链的安全声明能依靠的句子。B 是很好的**额外**屏障,是糟糕的**唯一**屏障。

### 2.4 A 还顺带化解了可用性与审查依赖

A 之下 prover 偷不了,所以 prover 不必是 Qumbra。社区节点、矿池、付费市场都能替手机证明;
中心服务变成多个提供方之一。B 之下 prover 永远只能是"经 attested 的 Qumbra 认可镜像",
[`backend-assisted-proving-security.md`](backend-assisted-proving-security.md) §7 的单一
运营方可用性与审查问题因此永久存在。

### 2.5 为什么可以在测量之前裁定

`remote-proving-decision.md` §9.3 写"不要从估算行里选"。本裁定没有:§2.1–2.4 没有一条是
数字。它们是层次、顺序和信任模型的事实,任何测量都改变不了。测量仍要决定的事列在 §4 ——
而那些全部是*实现*的门槛,不是基础的选择。

## 3. A 不给的东西,说清楚

- **A 过不了"看不见/不可链接"这道门。** 普通 worker 仍能看到被选的 note、金额、收款方
  明文、nullifier、设备身份、IP 和时间,并且拿到 full-viewing 级别的 `nk`。这是隐私缺口,
  不是资金安全缺口,而它正是之后叠 B(或多运营方证明)要解决的。
- **A 需要对绑定性设计规范做带日期的更正** —— 即"单体 STARK、无按笔签名"那条决策。
  更正由 Larry 在设计仓库完成,且必须在 lab 的电路或 wire 动之前落地
  (`remote-proving-decision.md` §9.4)。
- **A 是 T2 re-mint 级别的改动。** note/`rkm` 绑定、AIR 与公共值、交易 wire、节点验证、
  交易标识、genesis。

## 4. A 怎么推进 —— 建议,不是裁定

以下是评审者对 §9.1 授权 spike 的建议。写出来是为了让 spike 有一个起点,每一条都可以被
其测量推翻。

1. **叶子默认用 ML-DSA-44,不用 WOTS+。** 它无状态,`remote-proving-decision.md` §6 里的
   回滚/密钥重用 P0 直接消失而不是被管理;它是有公开测试向量的 NIST 标准,实例化不完整的
   P0 也一并消失。代价是比 WOTS+ 那一行每笔多约 3.1 KB(估 ≈166 KB,仍低于 b4 的
   ~236 KB)。WOTS+ 和随机索引 WOTS+ 留在对照里作为将来的尺寸优化,不作上线路径。
2. **先写 dummy 槽位规则。** #219 的 latch 让 slot 1 可以是 prover 侧的 dummy,没有 note
   也没有密钥树。它的授权规则(手机临时密钥、latch 路径绑定该密钥而不是树路径、仍然隐藏
   真实 input 数)是 spike 的第一个交付物,因为规范的其余部分都依赖两个槽位有同一个公共
   形状。
3. **保留 [`hash-ots-spend-authorization.md`](hash-ots-spend-authorization.md) 的结构性
   接缝:**每地址树根放进 `rkm` 的空闲 Keccak rate、32 字节叶子、电路内证成员关系、节点在
   STARK 验证之前原生验签。换的是原语,不是接缝。
4. **B 的机密虚拟机适配车道并行跑,不放在关键路径上。** 它便宜,其结果决定 B *何时*叠上,
   不决定 A *是否*推进。

工作量,按 Claude 会话小时计(墙钟时间取决于会话怎么安排):规范 + 向量 + dummy 规则
≈ 5 h;电路改动含域分隔复查 ≈ 15–20 h;wire、节点验证、钱包密钥层 ≈ 15 h;re-mint 本身
走现有流程。**合计 ≈ 40–50 会话小时**,另加 rig 上的 2^19 prover 测量(机器时间,不算
会话时间)。设计规范更正和 T2 launch 排序是 Larry 的步骤,不在此估算内。

## 5. 本裁定改变了其他记录的什么

- `remote-proving-decision.md` §9.3 已解决:上线安全基础是 A。§9.1(spike)、§9.2
  (B 车道,现为并行)、§9.4(规范更正)和 §9.5 原样保留,仍是实现的门槛。
- §8 的上线门槛不变;A 必须逐条通过所有适用项。
- `backend-assisted-proving-security.md`、`hash-ots-spend-authorization.md`、
  `phone-self-proving-reopened.md` 均不因本裁定而修改。

## 6. 交接时的范围

- 没有代码、电路、wire、genesis、云资源或部署改动。
- `CONSENSUS_CFG` 未触碰。
- 绑定性设计规范在其自身更正流程跑完之前保持原样。
