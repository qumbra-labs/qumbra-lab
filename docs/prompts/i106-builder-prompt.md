# Builder prompt — issue #106：一台空 data dir 冷启动的节点不该先挖自己的链

## 你的任务书

https://github.com/qumbra-labs/qumbra-lab/issues/106

**读 issue 全帖，然后读 coordinator 的任务书评论（最新那条）。** 17 条评论、四个会话在上面收敛过，而且**若干自信的早期结论被撤回过，其中三条是 coordinator 自己的**。任务书里列了撤回清单 —— **不要去追它们**，那是这根棒最容易浪费掉的时间。

## 🔴 这个 issue 是三件事绑在一个标题下，你只做第一件

| | | |
|---|---|---|
| **(1)** | **空 data dir 重启的节点从 genesis 挖自己的链而不是同步** | **你的** |
| (2) | 53 分 49 秒的卡死，主线程 103% CPU 在用户态，自己恢复了 | **不是你的。** 成因从没被确定 —— **不要修一个没人诊断过的东西** |
| (3) | `variants` 相关性：node0 的 key 被计入 ⟺ `variants=2`，8/8 | **不是你的。** T-ops 明说八个样本分不开"node0 制造分裂"和"node0 只在分裂已经形成时才被计入" |

**(1) 是挡着铸链和演练的那一件**（`qumbra-deploy/OPERATOR.md` §4）。(2)(3) 留在 issue 上继续开着。

## 🔴 #130 (a) 不修这个 —— 别假设它顺手解决了

(a) 昨天落地（PR #142），lag 非零时拒绝挖矿。**在这里帮不上忙。** 门是：

```rust
if self.state_lag().is_lagging() { self.refuse_for_lag("mine"); return None; }
```

而 `state_lag` 比的是**节点自己的两个视图** —— `state.tip_height()` 对 `chain.tip_height()`。**空 data dir 冷启动时两个都是 0，lag = 0，所以它照挖。**

**这个门是自洽性检查，而一个什么都不知道的节点是自洽的。**

## 缺陷本身，对照 `main` `b98455c` 核过

**挖矿的门完全没有同步条件**（`qumbra-node/src/run.rs:1240`）：

```rust
if self.mining && self.last_mine.elapsed() >= self.mine_interval {
```

而本该告诉它的那个状态**说不出来**（`qlab-p2p/src/sync.rs:28-30`）：

```rust
pub enum SyncPhase {
    /// Not syncing — either caught up or no taller peer known yet.
    Idle,
```

**「已经追平」和「我还不知道有谁比我高」是同一个变体。**

这是这个仓库反复出现的形状最纯的一次 ——**一个什么都不知道的节点，和一个知道自己已经完成的节点，无法区分** —— 也是 2026-07-26 以来的第十个实例。

## 真正的活是那个设计张力，不是加个 if

**你不能简单地要求"有 peer 才挖"或"收到 header 才挖"。** 一张全新网上的第一个节点**合法地没有 peer 且必须挖**，否则网永远起不来。`deploy/deploy.sh` 是拿一个 genesis 起四台主机的 —— 你造的东西**必须同时**让那张网起得来、**并且**让 node0 在重新 roll 时不分叉。

任务书里三个要带理由表态的点，第一个就是这个。**每个选项都有失效模式，说出你那个的** —— 比如一个墙钟宽限期，是在一个块时间 75 秒、RTT 达到 223 毫秒的网上做时序假设。

## 验收里最容易被做丢的一条

- 一个测试：**真正的第一个节点**（没有 peer、新 genesis）**确实会挖**，好让网起得来。

**这是修法太钝时会挂掉的那一个 —— 点名它。** 只测"不该挖时不挖"的棒，会交出一条永远起不来的链。

## 工作规则

- **worktree + PR，绝不直推 main。** `git worktree add ../qumbra-lab-i106 -b claude/i106`，第一条回复里说出路径
- **完整无过滤 `cargo test --release --workspace -- --test-threads=1`，报原始总数。** `main` 现在是 **915 passed / 0 failed**（coordinator 在 PR #141 上独立核过），所以应该是 915 + 你的测试数。**对不上先说这件事，别先解释别的**
- 跑重活前看 **[#64](https://github.com/qumbra-labs/qumbra-lab/issues/64)** 最新评论的队列并报起跑/收工。四根 Multica 棒在飞，**一次只能一个完整套件**
- STOP-POINT：任何 FROZEN 常量、任何新 codepoint、任何 `BlockBody`/`BlockHeader` 改动 —— 报告并等
- **卡在非 STOP-POINT 的判断上：取小的那个动作、标为可分离、在 PR 里写"我问了并继续了"。不要等 coordinator。**

## 交付

一个对 `main` 的 PR，**不关闭任何 issue** —— (2) 和 (3) 让 #106 继续开着。
