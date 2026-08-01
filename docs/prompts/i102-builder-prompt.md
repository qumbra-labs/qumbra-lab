# Builder prompt — issue #102：让成熟度成为结构，而不是一条建议

## 你的任务书

https://github.com/qumbra-labs/qumbra-lab/issues/102

读 issue 正文，然后读 **coordinator 的任务书评论**（最新那条）—— 你的范围、四个要带理由表态的点、STOP-POINT、验收判据。

**方案已经裁完了：option (b)，延迟插入叶子。** 你的活是实现它，以及论证 (b) 本身没有裁到的部分 —— **不是重开这个选择**。如果你认为 (b) 错了，**在动手之前**发在 issue 上，带理由。下面"为什么是 (b)"那段是你要推翻的东西。

## 标题会误导你，实际情况比它记录的还糟一档

标题读起来像"一条共识规则只在 mempool 层执行"。真实情况分三级：

`COINBASE_MATURITY_BLOCKS = 144` 是 **FROZEN §2 共识**（`qlab-node/src/emission.rs:49`，被 `params_audit.rs:352` 钉住，`genesis.rs:201` 烤进 genesis 文件）。

全仓库执行它的地方**只有一处**：`Mempool::admit`，`mempool.rs:434`。grep 这个常量 —— 其余每一处都是文档注释、测试、或显示字符串。**`validate_body` 和 `apply_state` 里没有成熟度检查。** 所以今天，一个含有未成熟 coinbase 花费的块**是合法共识**。

### (i) 声明由提交者控制

`Mempool::admit` 的 `spends_coinbase: Vec<Hash32>` 是**参数**（`:411`），循环在 `:432`。声明 `vec![]` 就跳过整个循环。模块注释自己承认了：*"That declaration is only as good as the submitter."*

### 🔴 (ii) P2P 线路上它不是 fail-open，是死代码

`adapter.rs:738`：

```rust
match self.mempool.admit(tx, vec![], &self.state, &self.verifier) {
```

**硬编码空。从 peer 来的每一笔交易都声明"我不花任何 coinbase"，所以那个循环永远迭代零次。**

这是 #123 faucet 那根棒发现并记为"#102 比 #102 自己记录的宽一个 seam —— 是线路，不只是钱包 RPC"的东西。值得直说：**一条 FROZEN 的共识规则，在唯一承载别人交易的路径上，零执行。**

### (iii) 未知 commitment 直接放过，而且每次重启后 map 是空的

```rust
if let Some(&created_at) = self.coinbase_notes.get(cm) {   // mempool.rs:433
```

未知 `cm` 从 `if let` 落空，然后通过。而这个 map 只由 `record_coinbase_note` 填，它唯一的非测试调用点是 `on_block_connected`（`mempool.rs:503`）—— 所以它只知道**本进程运行期间**连上的块。`NodeRpc::new`（`rpc.rs:252-255`）在收到一个**已经 replay 过的** `Node` 之后才建 `Mempool::default()`，所以**任何一次重启之后，所有历史 coinbase 都是未知的，花它们一律准入。**

### 外加：#130 在单次运行内就让它继续退化

`on_block_connected` 只在 `ingest_block` 的成功臂被调（`adapter.rs:725`），而 #130 表明那一支在状态机落后于 fork choice 之后就被跳过。所以在一台失同步的节点上 `record_coinbase_note` 干脆不再被调用，(iii) **不用重启**就退化成完全 fail-open。

你不需要修那个 —— #130 (a) 是单独派的棒 —— 但**不要把你的修法建立在 `on_block_connected` 会跑这个前提上。**

## 为什么是 (b)，以及为什么理由记的是隐私而不是重组

`mempool.rs:53-58` 早就记下了备选：

> *"append the coinbase leaf at `h + 144` rather than at `h`, so no anchor contains the leaf until it has matured and an immature spend is **unprovable** rather than refused-by-policy."*

**裁定的依据是 §6 的隐私泄露（一个当下的缺陷），不是重组后备（一个休眠的缺陷）。**

泄露就是 `spends_coinbase` 这个声明本身：Qumbra 只有一个全局屏蔽池、**没有透明层**，要求提交者点名自己花了哪些 coinbase note，等于把这笔花费和那个 coinbase 链起来，塌掉的正是新用户第一笔交易的匿名集。**一个只有在花费者自我去匿名时才生效的门，不值得修。**

(b) 直接删掉声明的必要性 —— 这才是它是"修复"而不是"同一个想法的加强版"的原因。它还让规则变成**结构性**的：unprovable 胜过 refused-by-policy，因为它对一个说谎的提交者、一个绕过 mempool 的 peer、和一台重启过的节点都成立。

## 🔴 排序上的硬约束，请在 PR 里回述确认

**(b) 改变了每个高度上树的内容，因此从高度 1 起每一个 root 都变。**

- **genesis hash 本身不动** —— genesis 没有 coinbase leaf（`coinbase.rs:269` 断言 `coinbase_note_leaf(0, &genesis) == None`），header 也不承诺树。所以钉住的 genesis hash 不因这个改动而移动。
- **但它从高度 1 起就是一次硬共识分叉。** 分处两侧的节点算出不同 anchor，会互相拒 body。
- 因此**它必须落在新网启动之前**，即 `qumbra-deploy` OPERATOR §4 step 4（铸新 genesis）之前，不是之后。落在之后就得铸第二次。**在 PR 里说你理解这是铸链前的改动。**
- **`COINBASE_MATURITY_BLOCKS` 保持 144，含义不变。** 你改的是规则在哪里执行，不是规则。**想改这个常量就是 STOP-POINT。**

## 两个我觉得真会出问题的表态点

四点全在 issue 的任务书里，这里把最可能翻车的两点提前。

### 位置 3 —— 延迟插入放在哪，必须 replay 一致

`apply_state` 是所有状态变更（新应用和磁盘回放）唯一的漏斗（它自己的注释这么说，#77 把它立成不变量）。一个欠在 `h + 144` 的 leaf，是在应用块 `h + 144` 时根据块 `h` 的信息插进去的 —— 所以这个机制要么**不靠额外状态就能撑过 replay**，要么必须**把"欠什么"持久化**。

**说是哪个，并测 replay 路径。一个回放出与自己构建时不同的树的节点，是跟自己共识分叉。**

### 位置 2 —— 别让"未成熟"和"不存在"对持有者不可区分

今天钱包从 mempool 拿到的是 `ImmatureCoinbase`。(b) 之后 leaf 不存在，失败模式变成"没有 membership witness" —— 而那**和一个根本不存在的 note 给出的信号是同一个**。

这正是这个仓库反复出现的形状：**一个缺席读起来像一个健康的空状态**（#104、#106、#113、#130、#134，加 #102 自己的 fail-open，六个实例）。`qumbra-faucet` §6.2 已经裁过"服务不了的 faucet 用高度拒绝而不是排队"；这里欠一个等价的东西。**论证是什么。**

## 明确不在范围内

- **#130** —— 单独派了 (a)。不要修；不要依赖 `on_block_connected` 会跑。
- **#134 / #135 / #136 / #137** —— 好奇可以读，不要碰。
- **2×2 电路。** (b) 被选中的部分原因就是它**不需要动电路**。**发现自己在 `qlab-air` 或 `qlab-consensus` 里就停下来报告。**
- 不动 FROZEN 常量。不加 codepoint。不动 `BlockHeader`。动 `BlockBody` 或改"root 承诺了什么"是这根棒的实质 —— 但**需要动任何 payload 的格式就是 STOP-POINT。**

## 验收

- 一个测试：未成熟 coinbase 花费是 **unprovable** —— 没有任何合法 anchor 含那片叶子 —— 而不是被策略拒绝。这是全部要点，点名。
- 一个测试：花费恰在 `minted + 144` 变为可能，早一个块不行。`qumbra-faucet/src/harvest.rs` 现有测试把边界钉在 `minted + COINBASE_MATURITY_BLOCKS − 1`（`:62`）；**显式地跟它们对账，不要不加说明地改它们去迁就新行为。**
- **一个 replay 测试**：造一条跨过至少一个成熟延迟的链，从磁盘重启，断言重建出的树和 roots 完全一致。**不可谈判** —— 见位置 3。
- 一个测试：线路路径不再能准入未成熟 coinbase 花费，**经由 `ingest_tx`**（那个 `vec![]` seam）验证，不能只走 mempool API。
- 完整无过滤 `cargo test --release --workspace -- --test-threads=1`，报**原始总数**。coordinator 会独立重跑；**一个对不上的过滤后数字，比不给数字更糟。**
- 跑重活前看 **issue #64 置顶评论**的机器状态，并在 PR 里说你等了没有。

## 工作规则

**worktree + PR，绝不直推 main。** `git worktree add ../qumbra-lab-i102 -b claude/i102`，第一条回复里说出路径。一次只跑一个 release 套件（峰值 16–30 GB / 36 GiB）。你不能做后台工作。**卡在非 STOP-POINT 的判断上时：取小的那个动作、标为可分离、在 PR 里写"我问了并继续了"。不要等 coordinator。**
