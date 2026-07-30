# Builder prompt — issue #130 **part (a) only**：让状态机追上它自己的链

## 你的任务书

https://github.com/lai3d/qumbra-lab/issues/130

读 issue 正文，然后读**两条**评论，顺序很重要：

1. **QUM-18 的 research 评论**（历史 body 该怎么传）。它是 (b) 和 (c) 被排除出你范围的依据，而且它**纠正了 coordinator 早先评论里的四点**。**research 与 coordinator 冲突时，以 research 为准。**
2. **coordinator 的任务书评论**（最新那条）—— 你的范围、STOP-POINT、验收判据。当 spec 用。

再读 **https://github.com/lai3d/qumbra-lab/issues/104** —— 这不是可选的，它改了"做完"的定义。见下。

## 先说清楚：这根棒只做 (a)

#130 被裁成三件可分离的事。**(b) state sync 和 (c) 历史 body 传输不在你范围内，不许开工。**

```
(a)  不动 wire   → 你的棒。四个 §4 演练的前置
(b)  动 wire     → T1,而且信任模型要 Larry 裁,不是你也不是我
(c)  一个 codepoint → T1 之后,而且 BlockBody::commitment() 可能在铸链前还会动
```

## 缺陷是什么，以及标题不会告诉你的那部分

`NodeAdapter` 里是**两个不同的对象**（`adapter.rs:110`、`:114`）：

```rust
chain: ChainState,   // 共识 header 链 —— fork choice
state: MemNode,      // 状态机:commitment 树、nullifier 集
```

`ingest_block`（`adapter.rs:700-731`）把 body 的应用挂在 **header 的**判决上：

```rust
let outcome = self.submit_header(header);
if outcome == IngestOutcome::Accepted {
    match self.state.apply_block(header, body.clone(), &self.verifier) {
        Ok(_) => { self.mempool.on_block_connected(...); }
        Err(NodeError::NotExtendingTip { .. }) => { /* reorg lag — expected */ }
        ...
```

`Accepted` 的意思是 **header 是新的**，不是"状态机准备好接这个 body 了"。而 `apply_block`（`qlab-node/src/node.rs:295`）在 `validate_body`、`apply_state`、`append_record`（`:336`）**之前**就返回 `NotExtendingTip`。

**差一个块就不可恢复。** header-first 同步按设计就会造出这个差；任何加入运行中的网的节点立刻就有。此后每一个 body 都被永久静默丢弃。

## 🔴 最红的一条：那条注释本身就是缺陷

```rust
Err(NodeError::NotExtendingTip { .. }) => { /* reorg lag — expected */ }
```

**一条断言"丢块是正常的"的注释，就是没人去问它到底正不正常的原因。**

**不要换个说法再放一条安慰性注释回去。** 如果那里还留注释，它必须写"现在保证了什么"，不能写"什么被容忍"。

## #104 是这个缺陷的第一次观测，比 #130 立案早三天

T-ops 在 2026-07-29 记的生产现象：四台 T0 主机的 `blocks.log` 全部冻住，**四个不同大小、四个不同停写时间**，全在一次 73 小时运行的头 27 分钟内。它指的函数全对，猜的机制差一步 —— 它猜 append 失败被吃掉，实际是 **append 从来没被尝试**。

两个后果，第二个是范围项：

1. **有一个比任何单元测试都强的验收判据**：重启后的节点被观测到从自己的 `blocks.log` 回放，而不是从 peer 重同步。#104 手里有 before 态。
2. **(a) 必须修持久化路径，不只是内存路径。** 一个 buffer 回放进 state 却没走到 `append_record` 的实现，会让 #104 的症状在成因消失之后继续存活 —— 一条仍然不持久的"持久链"。**在 PR 里明说 buffer 过再应用的 body 确实被持久化了。**

`finalize` 也被同样影响，动手前先知道这件事：`finalize`（`node.rs:382`）在 `if !self.chain.set_finalized(hash)` 就退出，因为那个 store —— **状态机的**，不是 fork choice 的 —— 从没收到 checkpoint 指的那个块。它返 `Ok(false)` 而不是 Err，所以 ~450 次 finalization 一声不响。**查一下 (a) 是否也恢复了 finalize 的 append，无论是否都要说。**

## (a) 是三部分，第三部分才是运维真正看得见的

### 1. 把 body 的应用与 header 新颖性解耦

header 已经在手的 body 必须能被应用。**按高度升序**应用，让攒着的一段随状态 tip 前进而顺序排空，而不是一次公告只进一块。

**设计 buffer 之前先读 https://github.com/lai3d/qumbra-lab/issues/135。** `P2pNode::blocks`（`qlab-p2p/src/node.rs:55`）已经在缓每一个 *header* 被接受的块的 `(txs, coinbase, coinbase_rkm)` —— 无界、不淘汰、不持久。**你要的 body 极可能已经在内存里了**：faucet 节点报 state tip 4 的时候，手里握着块 6..14。

**对这个关系表态**，别在它旁边再造第二个 buffer：复用、替换、还是两个并存但生命周期不同 —— 在 PR 里说是哪个、为什么。#135（给那个 map 加上限）**不在你范围内**，但别把它弄得更糟。

### 2. 把 lag 数出来并放到线上

`state_tip` 对 `fork_choice_tip`，以及两者之差，上 `TELEMETRY` 和 `/metrics`。

- **`TELEMETRY` 是 append-only。** `run.rs:2128`（`the_pre_i84_telemetry_prefix_is_frozen_against_future_appends`）钉住 `PRE_I84_FIELDS: [&str; 15]`，并断言既有字段不许移动或改名。**新字段放尾部。** `qumbra-ops/` 里每个归档日志和分析脚本都依赖这条。
- **lag 为零时也要出值**，别省略字段，否则每个 parser 都要特判。`final=-` 和 #125 的 `age_field()` 是先例。
- `/metrics` 仍然只在设了 `metrics_addr` 时开（#87）。
- **⚠️ 别算第二遍。** #126 刚落的 `SupplyCoverage`（`qlab-node/src/telemetry.rs`）已经在推导这个 state-vs-fork-choice 比较了。**derive 一个出另一个，或者把共有的概念提出来。** 这个项目一周内三次判过 derive-don't-restate（#116、#102、#125），**第四份独立副本正是要防的那件事**。

### 3. lag 非零时拒绝执行不可靠的职责 —— 这才是重点那半

`state_tip < fork_choice_tip` 期间，节点必须**不**：

- **挖矿** —— 它产的块进不了它自己的状态机。见下面那段，这条不显然；
- **肯定地回答 `is_valid_anchor`** —— 那是拿一棵旧树去回答一条共识规则；
- **服务钱包** —— 对着错误前缀切出的 witness 是静默错的。

这是以太坊 optimistic-sync 的规则：**节点声明自己的视图是旧的，而不是自信地拿它办事。** 它是这一类缺陷里第一次会从四台 T0 主机上**看得见**的东西，也是 (a) 拦着演练而不只是个 bug fix 的原因。

**在 PR 里论证拒绝的形态。** 硬拒、阈值、降级模式都站得住；站不住的是一个看不见的拒绝，或者一个悄悄退化成"给个像样的答案"的拒绝。如果你发现第四项 lag 期间不可靠的职责，说出来 —— 上面那三条是我列的，不是按构造穷尽的。

### 为什么"矿工丢币"这条要单独讲

`mine_block`（`adapter.rs:586`）取 `parent_hash = self.chain.tip_hash()` —— **fork choice** —— 而 body 从 `self.state` 装配。于是节点挖出一个 fork-choice tip 的合法子块，`submit_header` 接受（它确实延长了 fork choice），然后 `apply_block` 因为 `header.prev != self.state` 的 tip 而拒绝。**coinbase 的 leaf 永远进不了树。矿工花不掉自己刚挖的币，而且不报任何错。**

这是四条后果里最锋利的一条，也是它需要自己的测试而不是被顺带覆盖的原因。

## 明确不在范围内

- **(b) checkpoint-anchored state sync** —— 要动 wire，而且信任模型要 Larry 裁。不许开工。
- **(c) 历史 body 传输 / `GetBlock`** —— T1 之后。
- **#134**（`AnchorNotFinal` 被归类为 peer fault，导致加入者封掉诚实 peer）—— 它自己的 issue。**但要确认你没把它扩大**：如果 buffer 里的 body 会被重试并再次拒绝，确认你没有按次罚 peer。**在 PR 里说你查了。**
- **#135** —— 读它、对关系表态、别修它。
- 不动 FROZEN 常量。不加 codepoint。不动 `BlockBody`、`BlockHeader` 或任何 payload 格式。**需要其中任何一样就是 STOP-POINT** —— 发在 issue 上并等。

## 验收

- 一个测试：state tip 落后于 fork-choice tip 的节点**把攒着的 body 应用掉并收敛**，升序，无需重启。点名。
- 一个测试：挖矿那条 —— 在领先于自己 state tip 的 fork-choice tip 上挖矿的节点，不得静默丢掉自己的 coinbase。**这是引出本 issue 的回归，它需要自己的测试，不能只是顺带覆盖。**
- 一个测试：第 3 部分的每一条拒绝在 lag 期间**触发**，并在收敛后**停止触发**。后半句才是防止它变成一个永久降级节点的那半。
- `TELEMETRY` 字段顺序测试**不加修改**地通过。
- PR 里给一行真实的 `TELEMETRY` 样本，lag 和不 lag 各一行。
- 完整无过滤 `cargo test --release --workspace -- --test-threads=1`，报**原始总数**。coordinator 会在 detached review worktree 里独立重跑；**一个对不上的过滤后数字，比不给数字更糟。**
- 跑重活前看 **issue #64 置顶评论**的机器状态，并在 PR 里说你等了没有、等了多久。

## 工作规则

- **worktree + PR，绝不直推 main。** `git worktree add ../qumbra-lab-i130a -b claude/i130a`，第一条回复里说出路径。落地后清理。
- **一次只跑一个 release 套件。** 峰值 16–30 GB / 36 GiB。
- 你不能做后台工作 —— 欠的东西必须在你这一轮里跑完。
- **卡在非 STOP-POINT 的判断上时：取小的那个动作、标为可分离、在 PR 里写"我问了并继续了"。不要等 coordinator。** 这条是因为 coordinator 自己当过两次瓶颈，而两次自行发挥的 builder 都做对了。

## 交付

一个对 `main` 的 PR，**不关闭任何 issue**（#130 留着给 (b) 和 (c)；#104 留到观测到重启回放为止）。PR 正文里要有：

- 你取的立场和理由 —— 特别是 buffer 与 `P2pNode::blocks` 的关系，以及第 3 部分拒绝的形态；
- 一行真实 `TELEMETRY` 样本，lag / 不 lag；
- 确认 buffer 过再应用的 body 走到了 `append_record`，以及 `finalize` 的 append 是否也恢复了；
- 确认你查过没有按重试次数罚 peer（#134 的地盘，别修也别扩大）；
- 原始无过滤套件总数，以及你等机器了没有。
