# M11 faucet —— 运行记录、测量与发现

*中文（翻译）· EN（技术细节以英文为准）: [`m11-faucet-run.md`](m11-faucet-run.md)*

Issue [#100](https://github.com/qumbra-labs/qumbra-lab/issues/100)。crate `qlab-faucet`（本仓库第 15 个）。

---

## 1. 结论先行：任务书的约束二写错了，coordinator 已确认这条更正

任务书说*"吞吐由证明速度决定，不由区块容量决定"*。不成立。要数的是 faucet 的 **note**，不是它的交易。

在 *n*×*n* bucket 里，faucet 花掉自己的 *n* 个 note，产出 *n* 个输出，其中 *g* 个给收款人，*n − g* 个作为找零回来：

```
Δ(faucet note 总数) = −n + (n − g) = −g
```

**每一次发放恰好消耗一个 note，在任何 bucket 尺寸下都一样。** 三条推论：

1. **任何交易都不可能增加 note 数量。** 自转账是 2 进 2 出，即 Δ0。所以"把国库预先切成大量小面额"这个策略在这里**不存在** —— 1→N 拆分需要输出多于输入，而定长等元数禁止这一点。**recut**（重切）可以自由改变 note 的*面值*（保和），但永远改不了它们的*数量*。
2. **更大的 bucket 摊薄的是证明，不是发放。** 8×8 可以用一个证明服务 7 个收款人（7 次发放 Δ = −7，仍然每次 −1）。冻结 §5 费用表给 4×4 和 8×8 定了价；只有 2×2 有 AIR，所以今天摊薄不可用 —— 但即便可用，note 预算也不动。
3. 唯一的流入是 **faucet 每赢一个区块得到的一个 coinbase note**。

于是可持续发放速率**就是** note 流入速率：

| 目标 | 需要 notes/min | 75 s 出块下供给 notes/min | 证明器占用率 @ 2.28 s |
|---|---|---|---|
| 1 次/分钟 | 1.0 | 0.8（**每一个**区块都赢） | 3.8 % |
| 10 次/分钟 | 10.0 | 0.8 | 38 % |

证明器能撑 **26.3 次/分钟**（60 / 2.28）。note 流入供给 **0.8/分钟**。**证明速度离成为瓶颈还差 33 倍。** 即使 1 次/分钟也已超出"赢下每个区块"的供给 1.25 倍，所以任何高于约 0.8/分钟的速率都在消耗预先备好的 note 缓冲。

2026-07-29 coordinator 在本 issue 上的裁决：前提更正**接受**；decision 2 原本的问法（"预切面额 vs 临时拆"）**是问错了问题**；按 note-count 模型建并在 PR 里论证。

## 2. 四条决定，以及实际取的位置

### 2.1 反滥用：运营方签发的一次性 ticket 是承重控制

issue #32 让分散地址真正不可关联（`rkm = H(nk ‖ D_R ‖ d)`），所以同一个人可以生成无限多个互不关联的地址，而链上没有任何东西能把它们连起来。因此控制必须在链外，且不能偷偷引入链上身份。

关键事实是：**威胁模型是队列占用，不是抽干。** 服务能力约 0.8 次/分钟，所以攻击者不需要抽干 faucet —— 只需要占住那 0.8/分钟。用攻击者成本说话，而不是机制名字：

| 控制 | 永久占住约 0.8 次/分钟的成本 |
|---|---|
| 按完整 IP 地址计key | 对 IPv6 **≈ 0** —— 一个 /64 就是 2⁶⁴ 个 key |
| 按 /24 计key | 约 100 个不同 /24；租一个 /16 就含 **256** 个，即 256 倍预算 |
| 按 /16 计key | 每租一个 /16 只有 1 倍，但那个 /16 后面每个诚实用户都是连带伤害 |
| 客户端 PoW 题目 | 与攻击者核数线性。要让占用成本达到持续一个核，题目必须约 75 核秒 —— 诚实用户等一整个出块间隔 —— 而 100 个核仍然买到 100 倍 |
| 运营方签发的一次性 ticket | 运营方的签名。**租不到**，因为稀缺物不是一种资源 |

**已建：** ticket 是控制；子网桶与全局桶是**明确标注**为防事故的前置过滤器 —— 它挡住重试循环和卡死的客户端，且在文档里写明它挡不住任何有意图的东西。ticket MAC 是 **Keccak 前缀 MAC**（`Keccak256(DS ‖ secret ‖ id)[..16]`）—— 在海绵结构上是可靠的，而同样构造在 SHA-2 上会是 bug —— 复用 `qlab_note::hash::keccak256`。绝不上链。

**检查顺序本身是一条安全性质**，而且两个方向都重要：

- ticket 有效性**最先**检查，所以无票洪水烧不掉服务预算。测试锁定：10,000 个无票请求后全局桶完好（`a_ticketless_flood_cannot_burn_the_global_budget`）。
- ticket **最后**才作废，在其他所有检查都通过之后，所以撞上限流的诚实用户不会丢票（`a_throttle_does_not_consume_the_ticket`）。

**ticket 是开关**（`TicketPolicy::Required | Disabled`），因为"多公开算公开"原本是 Larry 的未决项。coordinator 此后裁定 ticket 从第一天起开启，理由是：*一个总是空的开放 faucet，比一个能用的受限 faucet 更不开放。* `TicketPolicy::Disabled` 的文档注释写明了翻这个开关的诚实后果，而不是留给别人去发现。

**全局**桶的补充速率是**推导出来的，不是猜的**：每 `POW_TARGET_BLOCK_TIME_SECS` 一个 token，因为可持续速率*就是*每块一次发放。测试锁定（`the_global_budget_is_the_block_interval`）。

### 2.2 面额：不预切，因为预切不可表达

立场：没有面额策略可选（§1）。剩下的只有"花哪一对"，而这对预算完全没有影响 —— 无论怎么选 Δ 都是 −1。所以 `Inventory::select_pair` 优化唯一还自由的变量：**覆盖 `grant + fee` 的最小和已锚定对**。它最小化经过证明的价值、退掉两个最小的 note（使价值不会碎成越来越长的尾巴），并保留最大那个 note 作为储备 —— 只要**任何**单个 note 能覆盖 `grant + fee`，可行的对就一直存在。

**任务书要的两档备料代价**，用 note 而不是价值计（价值不是约束：一个 50 QMB 的 coinbase note 供得起五次 10 QMB 发放的*价值*，但只供得起**一次**发放的*note 数量*）：

| 速率 | 每块净 note 消耗 | 1,000 个 note 的缓冲能撑 |
|---|---|---|
| 1 次/分钟（1.25/块） | −0.25 | 4,000 块 ≈ **3.5 天** |
| 10 次/分钟（12.5/块） | −11.5 | 87 块 ≈ **1.8 小时** |

而 1,000 个 note 的缓冲只能靠**挖 1,000 个区块且不花**建立起来 —— 75 s 出块下约 20.8 小时墙钟。这就是备料方案：faucet 的缓冲以"赢下的区块数"计量。

有一个这个形状确实允许、而本 crate **不主动制造**的优化：如果某一对刚好加起来等于 `2·grant + fee`，一笔交易可以服务两个请求且不留找零 —— 一个证明两次发放，每次仍然 −1 个 note。刻意去造这样一对要花一次 recut（1 个证明）来省半个证明，净亏；所以代码只在库存免费提供时才用它。

### 2.3 证明：按需，因为 grant 证明在请求存在之前根本不可能存在

这比窗口更基本。grant 的 statement 通过 `cm_out` 绑定收款人的 `rkm`，所以**没有 grant 证明可以预生成**。唯一可预算的证明是自转账，而它们是 Δ0，什么也买不到。decision 3 的前半自动消解。

于是 24 小时窗口（`MAX_ANCHOR_AGE_BLOCKS` = 1,152 = 24×3600/75，`params_devnet.rs:151`）不是一个并不存在的队列的保质期。它是已建好的证明的**提交截止期**。处理方式：

- 绑**最新的**有效 anchor（`AnchorLease::acquire`）；
- 一个短的**自设租期** `CHECKPOINT_CADENCE_BLOCKS` = 8 块 = 10 分钟，即协议窗口的 1/144；
- 提交前的**实时复查**（`GrantPlan::is_submittable`）—— 这是承重的一半；
- 被拒时恢复输入，给请求者另一次尝试，且不消耗他们的 ticket。

为什么保守而不精确：`/v1/anchors` 发布 `roots`、`tip_height`、`finalized_height` 和 `max_age_blocks`，但**没有每个 root 的高度**（`qlab-node/src/rpc.rs:330`），所以持有一个 root 的钱包只能确定"现在有效"，无法计算它何时过期。加 `(height, root)` 对是载荷改动 —— **停车点** —— 所以只报告（§3 发现 3），不建。`AnchorLease::window_bound_blocks` 给出线路**确实**支持的上界，让运营方能*看到*租期在界内，而不是相信它在。

**被否决的替代方案，之所以记录是因为它是唯一可行的预生成设计：** 预铸一批 note 到 faucet 自己派生的地址，然后把这些 note 的秘密作为"持票即拥有"的凭证发出去。这样发放在请求时不花任何证明，anchor 窗口也永不适用。否决理由：faucet 对每个未领取的 note 都保留花费权（可以在领取人眼皮底下把它花掉）、第一跳对 faucet 不隐私、发放不再原子。它是一个穿着 faucet 外衣的托管代金券方案 —— 而如果 10 次/分钟哪天真成了要求，那就是走这条路。

### 2.4 私钥怎么放，以及损失上界

这条链的花费授权在**证明内部** —— 没有逐笔签名 —— 所以知道 `sk` 就足以花费，被攻破的损失上界就是*那把钥匙拥有的每一个 note，加上轮换之前的每一次发放*。

**诚实的负面结论，因为它改变了建议：小额热钱包在这里做不到。** 从冷钥匙给热钥匙补货本身就是一笔 2×2 交易，而按守恒律每一笔这样的交易恰好搬过去**一个** note（2 个冷输入 → 1 个到热 + 1 个冷找零）。维持 *n* 个 note 的热库存要花**冷钥匙的** *n* 个证明，而冷钥匙必须在线才能做出这些证明 —— 所以"冷"是算术不支持的一个虚构。

因此可辩护的姿态是反过来的：

- **限定钥匙范围。** `FaucetConfig::hd_account` 默认 **1**，不是 0：faucet 与主钱包共用一个 HD account，就把服务被攻破变成了钱包被攻破。测试锁定（`the_faucet_key_is_not_account_zero`）。
- **永不渲染它。** `Faucet` 的 `Debug` 手写并扣留 wallet；`TicketSecret` 的会打码（`the_secret_is_never_rendered`）；`PendingRequest` 的会截断请求者地址 —— 在一条隐私链上，日志轮转里一个完整地址是"谁申请过资金"的长期记录。
- **让轮换便宜**：从一个可以改指向的挖矿收款地址供资。
- **写成界：** 损失 ≤（自上次轮换以来挖出的块数）× `coinbase(h)` + 累积的找零。按 1,152 块（24 小时，一个委员会 epoch）轮换，就是一天的发行量和一天的服务 —— 在测试网上价值为零，真正的损失是**服务**本身和一个公开端点被接管。

## 3. 发现

### 发现 1 —— coinbase note 从未进入承诺树，所以挖出来的钱一分都不能花

`Node::apply_state`（`qlab-node/src/node.rs:340`）只 append `tx.commitments`；`Mempool::on_block_connected` 把 `coinbase_note_commitment(...)` 记进一个*注册表*。所以挖出的 coinbase note 没有叶子、没有 Merkle witness，**今天无法被一个真实的 2×2 证明花掉**。这个 `[devnet-placeholder]` 形状在 `mempool.rs` 自己的模块文档里写着，所以边界是已知的 —— 但它意味着 faucet 真正的资金通路（挖 → 成熟 → 花）尚未实现，而约束四的冷启动当下不是"3 小时"，是"永远"。

**coordinator 升级（2026-07-29）：** 由于 faucet 因此成为当下唯一的资金通路，而 `testnet-plan.md` §3 把 T1 定义为*"anyone can join, mine, transact"*，于是 `faucet 上闸 + 挖到的钱不能花 = T1 对"交易"是邀请制`。这是关于 **T1 是什么**的陈述，而且如果没人说出来，它会以副作用的形式发生。本发现现在是 **T1 前置项**，不是脚注；`testnet-plan` §3 与 join 文档的标注由 coordinator 落地并开 issue。

本棒不修：共识状态改动是停车点。

### 发现 2 —— 冻结 §2 的成熟度闸从面向钱包的路径上到不了

`NodeRpc::submit_tx` 调 `self.mempool.admit(tx, vec![], …)`（`qlab-node/src/rpc.rs:287`）—— `spends_coinbase` 被硬编码为空，所以 144 块的闸只有直接调用 `Mempool::admit` 的人能触到。它被测试锁定（`rejects_immature_coinbase_spend_then_admits_after_maturity`）在一个生产代码路径到不了的接缝上。

绑在**存在的**接缝上：`OwnedNote::coinbase_note` 携带来源，`GrantPlan::spends_coinbase()` 计算出直接调 mempool 的人必须传下去的申报（`a_coinbase_funded_grant_declares_its_maturity_obligation`）。本棒不修：面向钱包的管线/载荷改动是停车点。

### 发现 3 —— `/v1/anchors` 无法表达一个 anchor 的截止期

见 §2.3。`AnchorSet` 不带每个 root 的高度，所以设计文档说需要它的那个消费者 —— 一个要规划数秒证明的钱包 —— 算不出自己的 anchor 何时过期。一个字段就能修好；那个字段是载荷改动。报告，不建。

### 发现 4 —— faucet 跑不了 T0 那一档主机

一个 2×2 证明峰值 **11.78 GB**。Phase B-WAN 的主机是 AWS `t4g.small` = **2 GiB**。所以 faucet 不能与 T0 节点共用主机档位，也不能在约 24 GB 以下并发证明两次发放。这是从证明器而非本 crate 推出的部署约束，属于给 T1 主机定规格的那份工作。

### 发现 5 —— 运维层面的：四个并发证明测试会把机器 OOM 掉

首次运行时表现为 SIGKILL。在本 crate 内用一个进程级 prover 互斥锁缓解（见 §4），所以工作区套件的内存包线不变。之所以记录：下一个在多个测试里做证明的 crate 也会撞上。

## 4. 测量 —— 每个数都带口径

**机器：** Mac17,6（Apple silicon，18 核），36 GB 内存，macOS 26.5.2（build 25F84），交流供电。**构建：** `cargo test --release`，rustc 1.95.0，Plonky3 按 `Cargo.lock` 精确钉在 `=0.6.1`（本分支未改动）。**仓库 rev：** 分支 `claude/m11-faucet`，从 `main` 的 `077b3ff` 切出。**下面每个时间数都带这条注意事项：这台机器是共享的** —— 上面同时跑着一个活网络采样器和其他 agent，所以时间是偏上界，不是静机 benchmark。

| 量 | 值 | 口径 |
|---|---|---|
| grant 证明，均值 | **2.28 s** | n = 4 次发放，同一进程（`consecutive_grants_…`），`--test-threads=1`；最小 2.04 s，最大 2.54 s |
| ……复现 | **2.27 s** | 第二次运行，同机同 rev，n = 4（最小 2.16，最大 2.35） |
| 同一个 AIR 经 `qlab-demo` | 2.00 s、2.11 s | `./target/release/qlab-demo`，n = 2，同机同 rev —— 所以一次发放和任何别的 2×2 花费一样贵，本 crate 没有增加证明成本 |
| M3 记录的数字 | 1.6 s | **另一台机器；本次未复现。** 不要拿它与上面的数字作差 |
| grant 证明线路字节 | **145,609 B** | 在 `end_to_end_…` 中断言；等于 `qlab-consensus` 的 `consensus_wire_is_145609_bytes` 钉子 |
| 证明峰值内存 | **11.78 GB** | `peak memory footprint`，对测试二进制跑 `/usr/bin/time -l`，`--test-threads=1`，1 个样本。最大 RSS 11.90 GB |
| ……默认并行度下 | **11.78 GB** | 相同，因为 prover 闸把证明串行化了。1 个样本 |
| `qlab-demo` e2e 峰值（对照） | 11.89 GB 最大 RSS | 同机同 rev，1 个样本 |
| 证明器上限 | **26.3 次/分钟** | 60 / 2.28 s |
| note 流入上限 | **0.8 notes/分钟** | 60 / 75 s，每赢一块一个 coinbase note |
| 余量比 | **33×** | 26.3 / 0.8 |
| 验收套件墙钟 | 20.6–23.9 s | `cargo test --release -p qlab-faucet --test acceptance`，7 个测试，共 8 个真证明 |

在源码里带着自己算术的推导常量：`MAX_QUEUE_DEPTH` = 32（75 s ÷ 2.28 s = 32.9，下取整 —— 一个出块间隔的证明受限积压）；`FaucetLimits::global_refill_window_ms` = 75,000（出块间隔，即把 note 流入上限表达为速率）；`PROOF_LEASE_BLOCKS` = 8（`CHECKPOINT_CADENCE_BLOCKS`，anchor 窗口的 1/144）；`DEFAULT_GRANT_BESSEL` = 10⁹ = 10 QMB `[devnet-placeholder]`（2×2 挂牌费的 1,000 倍，即 1,000 笔交易的运行费）。

## 5. 验收项 → 测试名

| 项 | 测试 |
|---|---|
| 端到端：请求 → 交易 → 节点接受 → 请求者扫到，真证明 | `end_to_end_grant_is_scanned_by_the_requester` |
| 控制确实拦住了它声称拦住的东西 | `the_abuse_control_blocks_what_it_claims`（+ `policy::tests::the_gate_blocks_what_it_claims_to_block`） |
| ……且不拦正常请求 | `the_abuse_control_admits_ordinary_requests`（+ `policy::tests::the_gate_admits_ordinary_traffic`） |
| 连续 N 次发放不会卡在"没有可花的 note" | `consecutive_grants_do_not_wedge_and_the_wedge_is_named` |
| 超窗证明被拒，而不是被静默接受 | `an_aged_out_anchor_is_rejected_by_both_the_faucet_and_the_node` |
| 冷启动被命名，而不是一个谜之停滞 | `a_faucet_on_an_unfinalized_chain_reports_the_cold_start` |
| 成熟度申报被算出来 | `a_coinbase_funded_grant_declares_its_maturity_obligation` |

合计：**36 单元 + 7 集成 = 43 个测试，0 失败**（`cargo test --release -p qlab-faucet`）。`cargo clippy -p qlab-faucet --all-targets` 无输出。

有两条性质值得点名，因为测试是围着它们建的：

- anchor 过期测试里的**正对照**。两个 plan 绑同一个 anchor；第一个在 anchor 还新鲜时提交并被接受，然后第二个被放到超窗并被拒。没有这个对照，那次拒绝就无法区分"anchor 过期了"和"faucet 造的交易本来就是坏的"。
- **租期比协议更严，且被演示出来。** 规划后第 9 个块，faucet 拒绝提交，而此时 `is_valid_anchor` 仍为真 —— 发现 3 带来的保守性，是被跑出来的而不是被断言的。

## 6. 我没有验证什么 —— 具体地说

**我认为最可能坏掉的那一处，点名：** `ChainView::anchor_leaf_count` 通过从新到旧扫描前缀 root 来还原 anchor 对应的树前缀。那是**每次规划** O(叶子数) 次深度 32 的折叠，而树永远在长。在测试规模（≤ 8 个叶子）它是免费的；在一年的主网上不是，而我**没有**测过它在哪里开始不可接受、真实钱包应该改用什么。**我没有见过它在个位数叶子以上通过。** 它存在只是因为发现 3 堵掉了便宜的路；如果线路哪天带上 `(height, root)`，这个函数应该被删掉而不是被优化。

其他未验证项：

- **全量未过滤工作区套件。** 未跑 —— coordinator 在本 issue（2026-07-29）明确说由他在独立 review worktree 里跑。我只跑了 `-p qlab-faucet`，外加 `cargo check --workspace --all-targets`（干净；`qlab-bench` 那些既有的 unused-import 警告未触碰）。**来自我的工作区计数不存在，也不应被推断出来。**
- **4×4 / 8×8 摊薄的说法。** Δ = −*g* 的代数是通用的，但只有 2×2 有 AIR，所以"8×8 可以用一个证明服务 7 个收款人"是从元数推出的论证，不是跑出来的东西。
- **并发。** `Faucet` 按构造是单线程的，从不同时为多个请求做证明。想要 prover 线程池的部署方案没有设计过，而发现 4 说每个槽位需要约 12 GB。
- **持久化。** 库存、已用 ticket 集合和队列全在内存里。faucet 重启会丢掉 note 账目，并把此前用过的每张 ticket 重新放行。从链上恢复库存是可能的（找零 note 加密给了 faucet 自己的地址，`end_to_end_…` 证明 faucet 能把它扫回来），但**没有实现也没有测试任何恢复路径**。
- **任何监听器。** 这里刻意没有 socket（crate 文档）：`testnet-plan.md` §6 把"面向公众的运维加固"留作独立一行，而在那一行的决定存在之前把一个热花费钥匙绑到公开 socket 上，正是那一行存在要防的暴露。所以这里没有任何东西被真实 HTTP 客户端、畸形请求、slowloris 或 TLS 终止验证过。
- **签发 ticket 的 CLI。** `AbuseGate::issue` 是运营方入口；没有命令、没有 secret 供给流程、没有轮换流程。`TicketSecret` 从字节接管，本 crate 从不生成、存储或打印任何一个。
- **ticket 校验的时间侧信道。** tag 比较在分支前折叠了每个字节，但 `Ticket::issue` 每次校验跑一次 Keccak，我没有测过整条路径是否常数时间。它在限流器后面，那是缓解，不是证明。
- **静机上的证明时间。** 机器是共享的；每次运行 n = 4，复现一次。请把 2.28 s 当作"这台机器、这个构建、在普通共享负载下"。
