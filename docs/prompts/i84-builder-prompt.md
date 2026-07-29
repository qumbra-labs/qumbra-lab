# Builder prompt — issue #84：终局 checkpoint 的身份

## 你的任务书

https://github.com/lai3d/qumbra-lab/issues/84

**先读 issue 正文，再读 coordinator 2026-07-29 的那条评论。** 正文写于 07-26，评论写于今天——两者的范围差了一半，而差的那一半是你**不该做**的部分。

## 这根棒最容易犯的错：做了已经存在的东西

#84 正文要两样：**(1) 终局 checkpoint 的身份**，**(2) 终局所依据的票数**。

**(2) 已经在 `main` 上了**，#87 于今天（2026-07-29）落地时带来的：

    ROUND slot=3744 … have=15 need=15 voted=6,…,20 absent=0,…,5 variants=2

加上 `/metrics` 的 `qumbra_checkpoint_round_votes`、`qumbra_committee_signed_rounds_total`、`qumbra_checkpoint_split_rounds_total`。

**你要做的只有 (1)。** 本项目曾有一根棒被整条作废——分支全部丢弃——因为任务书写于陈旧的图景，而它照着建了已经存在的东西。coordinator 评论里那张"已存在"表是今天读代码写的，但**行号会漂**：自己核一遍，发现哪一行不对就发在 issue 上，别在它上面继续建。

## 一条已经找到的、具体的东西

`Checkpoint::signing_message()`（`crates/qlab-devnet/src/committee.rs:156`）已经是 `(height, block_hash, root)` 的规范化、域分隔序列化——**正是委员会成员签名的那串字节**。

    CHECKPOINT_DOMAIN ‖ height_le ‖ block_hash ‖ root

不要再造第二套编码。用它，或者说明你为什么不用。

## 🔴 两道陷阱题，别绕过去

**第一：`TELEMETRY` 是只能追加的。** `crates/qumbra-node/src/run.rs:1579` 有一条测试断言既有字段不得移动或改名，而 `qumbra-ops/` 下每一份归档日志和分析脚本都依赖这个。**新字段加在末尾。** 如果你觉得某个既有字段的位置不合理，写进 PR 正文，别动它。

**第二：没有终局时也必须输出。** 现在没终局时打的是 `final=-`。你的身份字段要有同样的待遇——**缺席不等于空**，否则每个解析器都得为它开特例。这一条最容易在"先跑通再说"的时候漏掉，而它会一路漏到归档里。

## 三条钉死项

1. **只做可观测性。** 不碰共识、不碰线格式码点、不碰任何 FROZEN v1.0 常量。若你发现必须碰，**那是停车点——停下报告，不要先重构再说。**
2. **`/metrics` 默认不开**，除非配置里设了 `metrics_addr`（#87 定的，别改）。
3. **不碰 `qumbra-deploy`**，不碰任何已部署主机。

## 四条要在 PR 里表态的决定

issue 评论里逐条写了，这里只列标题——**理由比选择值钱，而有依据的反对意见比赞同更值钱**：

1. 身份哈希算在什么之上（`signing_message()` 还是结构体字段）
2. 打印多长，以及跨节点碰撞的论证
3. 放在哪里：`TELEMETRY` 是必须的；`ROUND` 和 `/metrics` 你来论证。**特别是 `/metrics`——哈希作 Prometheus label 通常是基数反模式，这里它每个 checkpoint 才变一次。这个理由成不成立，你说。**
4. **是否同时输出"本节点的钥匙签了什么"**，而不只是"本节点终局了什么"。今天 slot 3776 上 16 把钥匙签了一个变体、5 把签了另一个，而**唯一查出来的办法是 ssh 四台主机、拷六个私有账本文件、哈希最后 80 字节。** 如果你认为这该是另一根棒，可以——但要给理由，因为**这一半才是让演练可判定的那一半。**

## 不要部署

T0 内网正在跑，四台在 `t0-wan-2`。**不要碰主机，不要改镜像。** 你的产出是一个 PR。

## 工作纪律(全部强制)

1. **独立 worktree**:

   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-i84-build -b claude/i84-checkpoint-identity

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **重活要问。** 定向测试随便跑(`-p qlab-node`、`-p qumbra-node`,不吃内存);**全量 `cargo test --release --workspace` 开跑前先问 coordinator**——rig 是共享的,并发两个 release 套件会 OOM。rig 状态见 issue #64 的置顶评论。**另外注意:`cargo test` 一律加 `--test-threads=1`。**

4. **分阶段提交。** 本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作。**

5. **不碰 `qumbra-design`**。若你认为设计文档该记某条,把确切措辞写进 PR 正文,由 coordinator 落地。

## 验收(issue 里的,重述因为第一条最容易做浅)

- **一个测试：两个节点在同一高度终局了不同 checkpoint 时，身份字段不同；终局相同时，字段逐字节相同。** 这条是整根棒的目的，做浅了就等于没做——不要只测"字段存在"。
- 一个测试：尚未终局时，身份字段存在且格式良好。
- 既有的 `TELEMETRY` 字段顺序测试**未经修改**仍然通过。
- PR 正文里贴一行真实的样本行，展示新字段。

## 一条会让你省事的先例

今天 slot 3776 的 16/5 分裂是一个**现成的真实用例**：把你的字段放上去，问自己"如果当时有它，那次分裂要几步能看出来？"答案应该是"四台 grep 一次"。如果不是，方案还没到位。

## 沟通走 GitHub,不走人(operating-model §3.3,必带)

**不要指望有人替你转述。** 向 coordinator 提问之后、以及动手做被提问的那部分之前,**先去 GitHub 查回复**:

    gh issue view 84 --json comments --jq '.comments[-3:] | .[].body'
    gh pr view <你的 PR 号> --comments

问题也发在那里,不要只写在自己的报告里——**写在报告里的问题没有人会看见。**

## 开 PR,不要合并

合并是 coordinator 的事,在独立验收之后。

## 报告

PR 正文写清:

- **四条决定**的选择与理由;
- **你核"已存在"表的结果**——哪几行对、哪几行漂了。这是任务书的自检,不是客套;
- 每条验收对应的测试名;
- **诚实剩余项**:点名你认为最可能坏掉的那个东西,并直说你没见过它通过。
