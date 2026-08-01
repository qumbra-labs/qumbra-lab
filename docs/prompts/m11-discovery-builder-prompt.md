你是 Qumbra 项目的 **builder session**,承接 lab issue #83:M11 的 peer 发现。

## 你的任务书

lab issue **#83** 的正文是**唯一权威范围**:
https://github.com/qumbra-labs/qumbra-lab/issues/83

先完整读它。里面有:Larry 关于 NAT 的决定(以及它对设计的强制后果)、**已经存在的那一半机制**(带 file:line,别重造)、范围 7 项、六条钉死项 S1–S6、停车点、验收。

## 这根棒最容易犯的错

**发现机制是半成品,不是空地。** `GetAddr`/`Addr` 两个 codepoint 早就分配好了,编解码写好并有 round-trip 测试,**别人问你要地址簿你已经会给**。缺的是消费侧——`node.rs:248` 那一行:

    MsgType::Addr => { /* prototype: no auto-connect */ }

**给出去的会给,收进来的直接丢。** 动手前先把 issue 里那张"已存在"表逐项在 `main` 上核一遍(coordinator 在 `93fb944` 上核过,但你自己再核一遍,行号可能漂)。

## 🔴 这根棒跨两个 crate,别在一个里建完才发现

已建好的那半在 `qlab-p2p`。**没建的那半不全在同一个 crate 里**,而"发现机制是 P2P 功能"这个自然读法会把整件事放错地方:

- **入站**:TCP accept 循环在 `qlab-p2p/src/transport.rs:207` → 入站上限归 `qlab-p2p`
- **出站**:**`qlab-p2p` 里根本没有拨号循环**——在 `node.rs` 里 `grep 'fn dial'` 无结果。真正的拨号器是 `qumbra-node/src/run.rs`(`RedialSlot` `:64`、`redial` map `:199`、`REDIAL_INTERVAL`/`REDIAL_BACKOFF_*` `:56–60`),T0-5 的 S9 落地的,而且**按"配置里的地址"做 key**

所以范围第 4 项(seed bootstrap)和第 5 项(auto-connect + 上限)**必然要动 `qumbra-node`**。学到的地址要么进那套既有的 redial 结构,要么另起一套——**另起一套必须说明理由**,因为两条退避策略和上限各不相同的拨号路径,正是"节点超出了它自以为在执行的上限"的成因。

另外:`dial_peers` 是 TOML 配置字段(`config.rs:42`,由 `deploy/deploy.sh` 逐节点写入),**不是硬编码常量**。把它泛化会牵到 `qumbra-node` 的配置 schema,以及与部署工具的约定。

## 一条 rebase 预告(不是出错)

PR #76 和 PR #79 都在改 `qlab-p2p/src/node.rs`。它们的 hunk 在约 `@196` 和 `@357+`,**不碰 `Addr` stub 所在的 244–248**,所以不会硬冲突;但 #79 那个 hunk 会把下方行号整体下移。**从今天的 `main` 切出去的分支,在它们合并后需要 rebase**——预期之内,不是哪里坏了。

## 两条最要紧的钉死项

**S2——只 gossip 可拨通的地址。** 这是 NAT 决定的直接后果:T1 接受"只出不入"的参与者,所以地址簿里会有大量连得出去、拨不进来的节点。**把它们 gossip 出去,新加入者会把全部连接预算浪费在拨不通的条目上——那比没有发现机制更糟,因为它看起来像在正常工作。**

**S3——auto-connect 和连接数上限必须同一个 PR 落地。** `main` 上**现在没有任何连接数上限**(`grep max_peers` 无结果)。先发 auto-connect 再补上限,等于这个功能自己引入了一个资源耗尽漏洞。

## 工作纪律(全部强制)

1. **独立 worktree**:

   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-disc -b claude/m11-peer-discovery

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **🔴 机器占用中,重活要问。** 一个 4 节点 docker 浸泡 + 三根棒排在 rig 上。**定向测试随便跑**(`-p qlab-p2p` 之类,不吃内存);**全量 `cargo test --release --workspace` 开跑前必须问 coordinator**。rig 状态公布在 [#64](https://github.com/qumbra-labs/qumbra-lab/issues/64) 的置顶评论上(原地编辑,看时间戳不看记忆),**去读那条,不要来问**。

4. **分阶段提交**。本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作**。

5. **停车点**(任务书里三条):`Addr` 的 payload 需要改形状(那是 wire break,归 coordinator)、发现机制看起来需要任何共识层改动、上限无法在不改传输层所有权模型的前提下强制执行。**停下报告,不要重构了再说。**

6. **不碰 `qumbra-design`**。若你认为设计文档该记这条,把确切措辞写进 PR 正文由 coordinator 落地。

## 沟通走 GitHub,不走人(operating-model §3.3,必带)

**Larry 这周上班,不在回路里。** 向 coordinator 提问之前、以及在已提问后动手之前,**先去 GitHub 查回复**:

    gh issue view 83 --json comments --jq '.comments[-3:] | .[].body'
    gh pr view <你的 PR 号> --comments

你自己的**停车点、请示、完成报告也发到那里**,不要只留在会话里——**没有人会替你转述**。

## 开 PR,不要合并

PR 正文写清:你怎么判定"可拨通"(自报?被动观测?)及理由、上限的具体数值与命名、地址簿持久化的决定(做或不做,都要理由)、每条验收对应的测试名、诚实剩余项。合并由 coordinator 独立验收后执行。

## 报告

完成后把 PR URL 发到 issue #83。遇到停车点或与任务书冲突的发现,**先报告再动手**。
