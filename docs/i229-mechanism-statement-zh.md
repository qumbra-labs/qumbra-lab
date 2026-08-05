# #229 — 机理陈述(stage 0)

**配对文档:** [`i229-mechanism-statement.md`](i229-mechanism-statement.md) · 技术细节以 EN 版为准。

`docs/prompts/i229-fix-builder-prompt.md` 的 stage 0。**本分支不含任何修复代码。** 全部引用针对 `main`
`37a3fb5`,格式为 `文件:行号`。

---

## 1. 机理,一段话

一个节点先在线接受了某个区块、随后又 rewind 越过它,那个区块的 body 仍然留在
**`P2pNode::blocks`** 里 —— 即 #135 的有界 body 服务缓存(`qlab-p2p/src/node.rs:369`)。这个缓存是
"我有这个 body" 的**第三本账**,它位于 P2P 层而不在状态机里,而且**当区块离开已应用链时没有任何代码
把它从缓存中移除** —— 它唯一的写入口是 `insert`,采用"最低高度优先"淘汰(`node.rs:330-350`)。

之后 fork choice 转到该区块上,状态机需要 `fork + 1` 处的 body,请求方正确地去索要它(`bask=1@…`)。
对端以整体 body 的 `BlockAnnounce` 提供服务。然后 `on_block_announce` 的
**"我们已经持有这个 body" 提前返回**(`node.rs:1833-1839`)看到 `self.blocks.contains(&bh)` 为真,
清掉在途请求、把 `body_fetch_progress` 置为 `true`,并**在不调用 `ingest_block` 的情况下 return** ——
于是 `buffer_body` 从未执行,body 从未进入 `pending_bodies`,`rejoin_main_chain` 的门永远读到
`Missing`。下一轮请求再问,对端再服务,提前返回再触发。**这个循环以 tick 速率运行,直到缓存把该条目
淘汰**;那一刻同一次到达走进 ingest 路径,rewind 发生,累积的 body 在一趟里升序排空。

**层次就是已裁定的 (c) —— 而拦截点比大家寻找 (c) 的位置高一层。** 本 issue 至今的全部引用都在
`NodeAdapter` 内搜索(`buffer_body`、`is_body_worth_holding`、`pending_bodies`、
`rejoin_main_chain`)。body 根本没到 `NodeAdapter`:它在 `P2pNode` 里、在 `ingest_block` 被调用之前
就被丢弃了。

## 2. 这个定位是演绎,不是推测

本线程已为"看起来合理的故事"付过两次代价。这次不是故事:归档数字通过排除法把行号锁死。

`body_reqs` 在 `node.rs` 中**恰好有三个**移除点(grep 完备):

| 位置 | 行 | 含义 |
|---|---|---|
| 过期 `retain` | `1018-1019` | 条目超过 `BODY_REQUEST_TIMEOUT_MS` = 15 s |
| 提前返回,"已持有" | `1834` | **不调用 `ingest_block`** |
| ingest 之后,"现已持有" | `1867` | 仅在 body 确已持有时到达 |

`note_body_ask`(`node.rs:1059`)**每次插入 `body_reqs` 调用一次**,`asks` 计每一级
(`node.rs:542-546`)。因此 asks / 未决时长 = 重新插入速率,而重新插入速率受移除速率约束。

**2026-08-03 09:23:56Z、node0 的读数:** `ask h=2984 id=4f2932d634b9 age_s=1200 asks=2195`。

- 1,200 s 内 2,195 次 = **1.83 次/秒**。
- 仅靠过期路径,上限是 **15 s 一次 = 0.067 次/秒**。
- **27 倍于上限。** 所以移除发生在 `1834` 或 `1867`。
- `1867` 要求 body 已被持有,那会结束搁浅。它没有结束。⇒ **`1834`。**
- `1834` 的条件是 `self.blocks.contains(&bh) || self.node.has_stored_body(&bh)`。
  `has_stored_body` 即 `self.state.chain().block(hash).is_some()`(`adapter.rs:1955-1957`)——
  **已应用存储**,与 `missing_body_hashes` 排除时所用的谓词完全相同(`adapter.rs:2013`)。该哈希
  当时**在**索要集合内(`bask=1@2983`),所以这个谓词为**假**。
- ⇒ **`self.blocks.contains(&bh)` 为真。** 就是这个服务缓存。

这条链上没有任何一步是对意图或未观测状态的推断。它只用到:asks 计数器、三个移除点,以及两个谓词
读同一张 map 这一事实。

## 3. Stage 0 的五个问题,按顺序

### Q1 —— 代码顺序:`breq` 自增相对于"停止应用"的位置

**`breq` 是在 `tick` 末尾采样的 `self.body_reqs.len()`**(`node.rs:934`),在
`request_missing_bodies` 之后(`node.rs:925`)。索要集合来自 `missing_body_hashes`
(`adapter.rs:1993`),其基点是 `state_fork_point()`,当 `top <= base` 时返回空 —— 即**已应用 tip 在
主链上时**。

**代码里只可能有一种顺序:先冻结,后索要。** "偏离主链"与"有东西可索要"由**同一个**比较得出 ——
`state_fork_point() < state.tip_height()` —— 所以索要集合不可能先于重分类变为非空。
`missing_body_hashes` 没有别的触发器、没有定时器、没有对端输入。

🔴 **因此索要是症状,被门控的前提向"应用侧"落定。** 30 s 同 tick 的特征无需再做区分:顺序由构造
决定,而不由括界决定。stage 1 若把修复对准请求方,就是对准症状。

**并且搁浅期间 `breq` 不可能读到 0,这正是 5/5 实例每个 tick 都是 `breq ∈ {1,2}` 的原因。** 条目在
served 回答到达时被移除,又在同一 tick 稍后被 `request_missing_bodies` 重新插入,而遥测采样在其后。
振荡不可见,水位可见。

### Q2 —— 什么让一个 `slag=0` 的节点翻成 `schain=fork`

`schain=fork` 就是 `applied_tip().is_off_main_chain()`,即 `state.tip_hash() !=
chain.main_chain_hash_at(state.tip_height())` —— 两侧都是本地的(`qlab-node/src/telemetry.rs:380-391`)。
在一个已追平的节点上有两种事件能改变它,而**两次 onset 各占一种**:

- **到达的 header 移动了 fork choice**(`submit_header` → `insert_header`,`adapter.rs:1654`)。
  已应用 tip 未变,在节点脚下被重分类。**这是实例 4(node3):onset 那个 tick 前后 `stipid` 相同
  (`157ed35f7ad2`),`slag=0`,没有应用任何东西。**
- **节点自己的 rewind + 重新应用**把已应用 tip 落在一条不是(或不再是)主链的分支上。**这是实例 5
  (node2):`stipid` 在高度 573 不变的情况下 `5a26e60f2e5a` → `fcf3f5fb2e3a`。**

**两者是同一机理的不同最后一步,不是两条进入路径。** 搁浅条件不是"tip 如何被重分类",而是
"**`main[fork+1]` 的 body 是否在我的服务缓存里、同时不在我的已应用存储里**"。rewind 通常是创造该
状态的动作(它把区块移出已应用存储,`store.rs:395-411`,而 `ServedBodies` 毫发无损);fork-choice
移动则是让它变得**被需要**。实例 4 显示两者可以相隔一分钟:node3 在 `23:07:48.777Z` 的 rewind 创造
了状态,`23:08:48Z` 的翻转索取了它。

### Q3 —— `bask` 里的分叉点,以及意图死在哪里

`bask=N@F` 就是 `(missing_body_hashes(MAX_BODIES_IN_FLIGHT).len(), state_fork_point())`
(`adapter.rs:1131-1132`)。`F` 是分叉点;唯一的索要对象是 `main[F+1]`,而这**正是
`rejoin_main_chain` 在肯 rewind 之前要求出现在 `pending_bodies` 里的那一个区块**
(`adapter.rs:1429-1433`)。所以两次 onset 都"向后、低于自己的 `stip`"索要,恰是请求方在正确工作:
556 < 558、571 < 573,因为**分叉点**低于已应用 tip —— 那就是搁浅的定义。

🔴 **意图死在 `qlab-p2p/src/node.rs:1833-1839`** —— 即
`if self.blocks.contains(&bh) || self.node.has_stored_body(&bh)` 里的那个 `return`。这就是缺失的门,
定位到 `文件:行号`。它下游的一切都正确且被饿死:`buffer_body` 从不被调用,
`is_body_worth_holding` 从不被求值,`pending_bodies` 从不收到该 body,`rejoin_gate_observed` 诚实地
报告 `Missing`(`adapter.rs:1054-1069`),`drain_pending_bodies` 在那个高度无物可排。

### Q4 —— 同一高度上的 `stipid` 替换

`rewind_to`(`qlab-node/src/node.rs:877-932`)只用保留的祖先路径重建已应用链;被撤销的后缀离开已应用
存储、进入 #198 的 `retained` 占有归档。因此"rewind 到高度 *h* 后沿**另一条**分支应用缓冲 body"会
产生**同一高度上的不同身份** —— node2 在 `REWIND … → 16093980 @ 571` 之后于 573 处
`5a26e60f2e5a` → `fcf3f5fb2e3a`。node3 没有这一步,因为它在 onset tick 并未重新应用任何东西:它的
rewind 早在一分钟前发生,翻转是由到达的 header 造成的。

**所以这个替换是"rewind 那一刻哪条分支恰好有缓冲 body"的后果,不是第二种机理。** 它与节点是否搁浅
无关。

🔴 **并且它纠正了一个观测层面的谜团。** `23:07:48.777146Z` 与 `23:07:48.777194Z` 的两条 `REWIND`
(相差 48 µs、同一高度 557 上不同的 from-tip)**并不是两次同时发生的 rewind**。`REWIND` 是从日志
队列排出、按消息泵节奏批量打印的(`qumbra-node/src/run.rs:1585-1597`、`adapter.rs:1437-1440`),
所以相差微秒的两行只说明两个事件发生在前一个泵周期内的任意时刻、被一起打印。节点每次只持有一个
已应用 tip;两次 rewind 之间它把缓冲 body 应用到了第二个、不同的 557。**没有任何东西持有两个已应用
tip。**

### Q5 —— 为什么 #130 (a) 的升序追平不触发

#130 (a) / PR #142 应用的是**它已持有**的 body:`drain_pending_bodies` 升序遍历 `pending_bodies`
(`adapter.rs:1460-1494`)。它在 `NodeAdapter` 里。而 body 是在高一层的 `P2pNode` 里、在
`ingest_block` 被调用之前就被丢弃的。**#130 (a) 没有被击败 —— 它被饿死了。** 它的保证以"到达"为
前件("a body whose header is in this node's chain is applied as soon as the state tip reaches its
parent",`adapter.rs:2120-2122`),而本缺陷破坏的正是这个前件。

#178 的 `rejoin_main_chain`、#162 的保留规则、#182 的请求方同理:本 issue 引用过的每一处机制都是
对的。**恰好有一个接缝是错的,而它是唯一没被引用过的那个。**

## 4. 什么开启它、什么维持它、什么结束它

### 开启

两个条件必须同时成立,而且两者都很平常:

1. 节点曾**在线接受过某个区块** —— 一个 header 对它是新的整体 body `BlockAnnounce`,于是
   `complete_block` 缓存了该 body(`node.rs:1972-1980`;缓存以 `Accepted` 为门,而 `Accepted` ⟺
   `insert_header` 返回 `Ok`,`adapter.rs:1654-1671`)。自己挖出的块进同一个缓存(`node.rs:847`)。
2. 该区块**离开了已应用存储**(一次 rewind),且**fork choice 后来选中了它**(或它的分支),于是
   状态机再次需要它的 body。

两者都是常规的分支扰动 —— 两个 onset 窗口里每台主机都反复 rewind 1–2 块。**恢复的主机与搁浅的主机
之间唯一的判别式,是它此刻需要的那个 body 是否正躺在自己的服务缓存里。** node1 在同几分钟内穿过
了完全相同的 573 之争而没有搁浅,因为它的第二次 rewind(`5a26e60f @ 573 → 14146440 @ 572`)把
已应用 tip 留在了**主链上** —— `state_fork_point() == tip`,索要集合为空,没有可被饿死的东西。

### 维持

循环,加上四个都已被观测到的后果:

- **只要条目还在缓存里,`gate=missing` 就是永久的。** 全程 `bdrop=0`,因为确实什么都没被丢弃 ——
  为什么这个字段本来就看不到这件事,见 §5。
- **`pend=52`**:搁浅点**之上**高度的 body 持续到达、被接受、堆在 `pending_bodies` 里,而其中没有
  一个可应用。
- 🔴 **`uex` 永远无法武装 —— 这回答了 #222。** 提前返回把 `body_fetch_progress` 置为 `true`
  (`node.rs:1836`),每 tick 消费一次(`node.rs:931-934`),从而在 `observe_body_fetch` 里把
  `unserved_since_ms` 重置为 `None`(`adapter.rs:961-972`)。在搁浅节点上这**每个 tick**都发生,
  于是 #201 的豁免累积不出窗口。#222 的主流假设是"任何 body 到达都会重置计数器";更锐利的事实是
  **重置它的正是那个永远不会被应用的 body**。五个实例的每个搁浅样本都是 `uex=0`。
- **节点停止挖矿并在自己的 slot 上缺席。** 滞后门拒绝(`adapter.rs:1714-1736`),这拿走了它的算力
  和它的钥匙 —— 即 #223 命名的 quorum 余量代价、#226 命名的 variant 分裂。两者都不是本缺陷**修复**
  造成的;两者都是搁浅的下游。

### 结束

🔴 **`ServedBodies` 的淘汰,而且它不是意外。** `ServedBodies` 没有移除 API —— 唯一的写入口是
`insert`,它按 **最低 `(height, hash)` 优先**淘汰,直到回到 `MAX_SERVED_BODIES = 128` 之内
(`node.rs:107`、`node.rs:341-349`)。在只有 coinbase 的 T0 上 `MAX_SERVED_BODY_BYTES = 8 MiB`
不可达(每条权重是 `txs_weight + 40` B)。所以被困条目在大约 128 次插入把缓存低端推过它之后离开。
在那个 tick,下一份 served 副本走进 ingest 路径:`buffer_body` → `drain_pending_bodies` →
`rejoin_main_chain` rewind → 累积的 body 在一趟里升序排空,**而同一次 `on_block_announce` 调用在
1867 行清掉 `body_reqs`。**

**这就是 `breq → 0` 与 `stip` 解冻 5/5 同时发生、其中两次括到 61 s 的原因:它们不是两个相关事件,
而是同一次函数调用。** 也是追平为什么是单步(08-03 那次 88 块;实例 4 中 `slag 77 → 17` 约 16 分钟)
而不是渐进的原因 —— `pending_bodies` 早已装满搁浅点之上的区块。

**定量预测,并明示其为预测。** 时长 ≈ 128 / (每高度被接受的 body 数) 块 × 出块时间,故解冻时的
`slag` ≈ 128 / (每高度 body 数)。五个实例解冻时实测 `slag`:**76、84、约 70、77、74** ⇒ 每高度
1.5–1.8 个被接受的 body,这正是 1–2 块 rewind 扰动所隐含的兄弟块速率。1 h 25 m – 2 h 09 m 的时长
在实测 86 s 平均间隔下吻合。**这是一致,不是已验证** —— 唯一能验证它的测试见 §7。

> ### 🔴 2026-08-05 更正,来自 stage 1 的实测 —— 上面的算术不成立
>
> 淘汰实验已针对修复前的条件构建并运行。**定性结论成立,且现已被测量:搁浅由缓存淘汰结束。** 缓存
> 恰好填满 `MAX_SERVED_BODIES = 128` 条,已应用 tip 只在被困条目被顶出之后才移动。这就是"自愈从来
> 不是愈"这一发现,它已确认。
>
> **但关系式 `解冻时 slag ≈ 128 / (每高度 body 数)` 被撤回。** 在一个每高度恰好产生一个 body 的
> 双节点 sim 中,搁浅本应在第 128 次公告时结束。它没有:
>
> | 每个公告块的投递时间 | 解冻所需公告数 | 解冻时缓存 |
> |---|---|---|
> | 30 ticks | **142** | 128(满) |
> | 6 ticks | **325** | 128(满) |
>
> 该计数以容量上限为下界,并被**投递丢失**放大,只有当投递不再是约束时才收敛到 128。所以上限设定的
> 是时长的**下界**,而不是时长 —— 而我从 `slag` 74–84 **反推**出的"每高度 1.5–1.8 个 body"这个生产
> 系数,**并未被此处任何测量确立**。它只是与观测一致的一种算术,我不该把它写成解释。
>
> **产生这个差距的次级发现比被撤回的定律更有价值。** 是拒收循环自身的流量在饿死投递:V 以 tick 速率
> 反复索要、对端反复服务,被限流的帧被丢弃且刻意不计分(#91,位于解码之前),因此**该循环延迟了结束
> 它自己的那次淘汰 —— 网络越忙,搁浅越久。** 这与"意外可靠地到来"的预测方向相反,并且意味着那个
> ~2 h 常数根本不是常数:它是 `MAX_SERVED_BODIES` 个块的下界,加上节点自身抖动所付出的额外代价。
>
> **对 ROADMAP 更正的影响**(设计侧,归 coordinator):那一行可以说自愈是缓存淘汰到期而非恢复;
> **不可以**说时长是 `128 / (每高度 body 数)` 个块。

🔴 **这让"等待一场意外的期望时长"退役。** 该常数是一个缓存容量到期时间;2026-08-03 更正后留存的
ROADMAP 那句 *"等待之所以是可辩护的运维反应,是因为意外可靠地到来"*,现在有了机理:等待就是
`MAX_SERVED_BODIES` 个块。它可靠是因为它是个计数器 —— 这比被它替换的说法更强,而在运维上更糟,
因为它不随任何运维员能影响的量变化。

## 5. 这对记录意味着什么 —— 三处更正

1. 🔴 **`bdrop=0` 从来没有它被当作拥有的那种覆盖面。** `bdrop` 只来自
   `drain_pending_bodies` 的**应用失败分支**里的 `metrics.observe_body_refusal(...)`
   (`adapter.rs:1491`),别无他处。`buffer_body` 的准入拒绝(`adapter.rs:1371`)**完全没有计数器**。
   所以"bdrop=0,因此 `is_body_worth_holding` 没有拒绝它"在这里成立,但理由比原来给出的更强 ——
   `is_body_worth_holding` 根本**没被抵达** —— 而这个一般性推断并不成立:未来经由准入门进入的搁浅
   同样会读到 `bdrop=0`。**记为仪表缺口,本分支不修。**
2. **#198 推理过的正是这个死锁,而它止步于差一本账。** `qlab-p2p/src/n1.rs:228-233` 列出"已应用"
   的四个调用方,并对第四个说:*"`on_block_announce` 的 'we already hold this body' 提前返回 ……
   若被放宽,会让一个 rewind 越过某块的节点把重新公告的 body 当作冗余丢弃。那是同一个死锁挪了一个
   接缝,所以两个谓词按构造分开。"* 推理正确,结论对 `has_stored_body` 也成立。**`self.blocks` 是
   同一个 `if` 里的第三本账,而它不在那次分析里** —— 它早已免费地跨越 rewind 回答"我们有这个
   body"。
3. **"同一毫秒两条 `REWIND`"是打印产物**,不是状态机异常 —— §3 Q4。

## 6. 未知,如实命名

- **淘汰的算术是一致的,不是被测量的。** 没有任何东西统计缓存插入或淘汰,所以"128 次插入"是从五个
  实例解冻时的 `slag` 推出的,而非观测到的。一个淘汰计数器能定案;目前没有。
- **两条进入路径哪条占多数**未知,且对修复不重要。实例 4 由 fork-choice 移动进入,实例 5 由
  rewind-并重新应用进入;更早的三个实例完全没有 onset 覆盖。
- **节点能否在没有 rewind 的情况下落入同一陷阱** —— 经由"body 被接受并缓冲、随后被保留规则从
  `pending_bodies` 丢弃、同时仍留在服务缓存里" —— 在代码上可达(`adapter.rs:1512-1520`),且在遥测
  行上与本机理无法区分,唯一差别是它**会**抬高 `bdrop`。`bdrop=0` 对这五个实例排除了它,但不构成
  一般性排除。
- **07:08:48 / 07:09:38 的 50 秒顺序**(实例 4 的 onset 先于 finality 最后一次前进)与"搁浅把
  node3 的 5 把钥匙从它原本投的 variant 上移走"一致,但更正后的轮次表显示每个 slot 都闭合了,所以
  **本机理既不解释也不需要它。** 它仍属 #226 / #223 的地盘。
- **Tick 周期。** 1.83 asks/s 意味着搁浅主机上约 550 ms 的 tick。这并不异常,但未经测量,而且不
  承重:"27 倍于上限"的论证在任何快于 15 s 的 tick 周期下都成立。

## 7. Stage 1 继承什么(护栏,不是设计)

写来供裁定或退回,不预先占据修复的位置。

- **接缝是 `qlab-p2p/src/node.rs:1833-1839`。** 它在 P2P 层、纯节点侧,不触及任何消息类型、载荷或
  共识规则 —— **无线上或 genesis 变更**,因此无需 re-mint 即可 roll。若某个候选修复需要其中之一,
  那就是任务书点名的 STOP。
- **在改动任何东西之前先验证 §4 的复现**,且不需要主机:两个进程内节点,在某一高度制造分支之争,
  在线接受两个兄弟块(使两份 body 都进入 `ServedBodies`),rewind 越过最终获胜的那一个,断言只要
  缓存持有它,served 的 body 就永不进入 `pending_bodies` —— 然后淘汰它并断言恢复。**如果该测试在
  `main` 上不变红,本陈述就是错的**,stage 1 不应推进。
- **必须保住的健康恢复基线**:`breq → 0` ⟺ `stip` 解冻,同时发生,5/5。在 §4 之下这个同时性是结构
  性的(同一个调用点),所以保持 ingest 路径完整的修复会保住它;而在新位置清 `body_reqs` 的修复会
  静默地破坏它。
- **反向验收判据**:十五分钟内那六次健康 rewind 必须继续健康。任何修复都不得把"我在缓存里持有这个
  body"变成 rewind 触发器 —— 审阅者主张保留的"由到达驱动"这一性质并未被本机理挑战,应当在修复后
  存活。
- **仍然欠着、且价值仍居首的可观测项**(裁定的第 4 项):`BODYWAIT` 已经会说 `gate=missing` 和
  `mine=refused-lag`。它说不出的是**这个节点认为自己已经拥有它正在索要的那个 body** —— 那一句话本
  可以把这次诊断压缩到五分钟。
- **`adapter.rs:1341-1343` 的注释**仍以一个 `rewind_path` 并不强制的 rewind 深度主张来为 body 缓冲
  边界辩护(coordinator 自己在 2026-08-03 的更正)。本分支未改;归 stage 1。

## 8. 我没有跑什么

**在本陈述提交裁定时,分支内没有任何代码**,所以没有跑工作区测试套件,它也不是 stage 0 的门槛:
没有新增测试、没有触碰任何 crate,相对 `main` 的 `git diff --stat` 只有文档。没有取 rig 锁,
没有启动任何重任务。

**stage 1 已于 2026-08-05 获裁定放行,其运行记录在 PR #264 上**,包括复现在 `main` 上双向变红,
以及产生 §4 那处更正的淘汰实测。

**读过的证据:** issue #229 全文(正文 + 23 条评论)、`qumbra-ops/i229-onset-windows-20260805/`
(全部 8 份四主机日志),以及 `main` `37a3fb5` 上每一处被引用的行。没有对任何主机执行任何操作,
没有触碰任何主机。
