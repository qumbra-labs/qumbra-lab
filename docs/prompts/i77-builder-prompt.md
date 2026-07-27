你是 Qumbra 项目的 **builder session**,承接 lab issue #77:把区块体绑定到它的头部。

## 你的任务书

issue #77 的**正文**(缺口分析 + 修法)加上**两条** coordinator 评论——**"Task-book — bind block bodies to their header (2026-07-26)"** 和其后的 **"Addendum — four corrections to the task-book, before dispatch"**——共同构成权威范围。**两者冲突时以 Addendum 为准**:
https://github.com/lai3d/qumbra-lab/issues/77

正文是 coordinator **今天亲自核实过**的(不是转述报告):`validate_body` 只收 `&BlockBody`、结构上做不了这个检查;`ingest_block` 和 `apply_block` 都同时握着头和体、都没比对;全仓唯一一处断言在测试夹具里。**seam 的权威清单是任务书评论里那张对照表(含 file:line)加上 Addendum A2 的回放路径——正文里任何"几处"的说法都不作数**(A3)。

## 这个 bug 有多大

**最便宜的利用:把诚实的头配一个空体转发出去。** 空体让 `validate_body` 平凡通过(没有 tx 就没有坏 anchor、错费率、重复 nullifier、无效证明),头 PoW 有效被接受,空体被应用进状态。

后果不是"体不对"那么简单:两个诚实节点在**同一条头链**下持有**不同状态** → 同高度 finalized `root` 不同 → 诚实委员在同一高度签**不同的 checkpoint variant** → tally 分裂、**finality 停摆且无人可归责**(没人签两次,等价物检测不触发)。

不是资金安全问题(证明照验),是**一条未认证消息就能造成状态分叉 + liveness 断裂**。

## 钉死的决定(评论里有完整理由,别重开)

1. **检查放在任何 body 工作之前。** 成本不是问题——`body.commitment()` 是 O(区块字节),而紧随其后的 `validate_body` 要**验 STARK 证明**,贵几个数量级。**不要做缓存、惰性求值、或"只在同步路径检查"这类优化。**
2. **不匹配 = 作恶:拒绝**并**扣分**。注意这和 #70 的 S5 纪律**正好相反**,对比本身就是要点:未达 quorum 的投票集是诚实节点产出的诚实进展;而**不存在任何诚实方式产出一个与头部承诺不符的体**。
3. **用结构约束,不要靠纪律。** 多处 seam 各自"记得"一条规则,迟早会有一处忘记。首选让"未经检查的头+体组合"**难以表达**。**默认走候选 A(`validate_body` 收头部,让签名承载义务)**——Addendum A1 已撤回了候选 B(`StoredBlock::from_parts` 变受检构造器)的原始表述:它把检查放在 STARK 验证**之后**(`node.rs:244` validate_body → `:246` from_parts),违反 P1;而且磁盘日志回放路径直接反序列化 `LogRecord::Block` 调 `apply_state`(`node.rs:161`/`:180`),**根本不经过 `from_parts`**。仍想要 from_parts 形状的答案,必须显式说明这两点怎么解决。**门槛不变**:改完之后新增 seam 跳过检查必须是显式可见的。

   补一条设计观察(Addendum A1 尾段):`apply_state(&StoredBlock)` 才是状态变更的**真漏斗**——`apply_block` 和磁盘回放都经过它。但那是**另一件工作**:入口处按 P1 最先最便宜地拦对抗输入,`apply_state` 是拦"内部构造错误和回放损坏"的地方。两者都用就要说清哪个干哪个,别把一个当成另一个的替代。
4. **生产侧也要核(范围见 Addendum A4)。** 凡是**真正携带 `BlockBody`** 的生产路径,都必须把 `tx_body_commitment` 设成真正的 `body.commitment()`:adapter 的 `mine_block`(`adapter.rs:321`,已经是对的)、节点二进制、docker/deploy、以及同时构造头和体的测试辅助。**`qlab-devnet` 的挖矿链是 header-only、根本没有 `BlockBody`**(`mine_next(tx_body_commitment: Hash32)` / `mine_on` / `net.rs:68`),**不在范围内**——它只是把一个承诺值传过去,从不声称自己算这个值。你若认为它也该收紧,那是另一条发现,单独报告,不要并进来。

5. **还有一处 seam 我没列:磁盘日志回放**(`node.rs:161`/`:180`,头+体进状态、零校验)。见 Addendum A2:**要么查、要么写明理由豁免**(注意回放是 O(链长),重算每个 commitment 不是免费的)。两种答案都可接受,**不表态不行**。

## 会有存量测试挂掉 —— 每一个都是发现,不是杂活

大概率有若干测试把一个随手造的头和一个不相干的体配在一起,今天能过只是因为没人检查。**不要机械地回填 commitment 把它们糊过去。** 逐个判断是"单纯草率"还是"在悄悄依赖这个缺失的绑定",**在 PR 正文报告数量和分类**,如果其中任何一个暴露了第二个真问题,直说。

## 工作纪律(全部强制)

1. **独立 worktree**:

   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-i77 -b claude/i77-body-binding

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **🔴 机器被占,你的全量套件排第三。** 一个 4 节点 docker 跨 epoch 浸泡占着 rig 到**今晚约 22:00**;放行顺序是 **#74 → #24-D3 → 你**。现在能跑 `-p qlab-p2p` / `-p qlab-node` / `-p qlab-devnet` 这些小的(自用信心,不算验收)。**全量套件开跑前问 coordinator。** 绝不同时跑两个 release suite。

4. **分阶段提交**。本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作**。

5. **不动任何 FROZEN v1.0 常量。** `tx_body_commitment` 本来就存在、本来就在头部哈希原像里,字节布局不变,线路格式不变——**变的只是节点拒绝接受什么**。也不要重新设计 `body.commitment()` 的编码,那不在范围内。

6. **不碰 `qumbra-design`**。若你认为 `protocol-spec` 该写明这条不变量,把确切措辞写进 PR 正文由 coordinator 落地。

7. **`from_parts` 全仓有三个不相干的**(`StoredBlock::from_parts` 在 `qlab-node/src/store.rs:138` 才是本棒要的;另有 `qlab-cbserver/src/data.rs:202` 和 `qlab_devnet::committee` `:216`)。**一律写全限定名。**

8. **开 PR,不要合并**。PR 正文必须有:P3 你选了哪种结构约束及理由、每处 seam 的负向测试名(**含空体那条**)、扣分测试、存量测试破坏报告(数量 + 分类)、诚实剩余项。

## 沟通走 GitHub,不走人(operating-model §3.3,必带)

向 coordinator 提问之前、以及在已提问后动手之前,**先去 GitHub 查有没有回复**:

    gh issue view 77 --json comments --jq '.comments[-3:] | .[].body'
    gh pr view <你的 PR 号> --comments

你自己的**停车点、请示、完成报告也发到那里**,不要只留在会话里。**Larry 不是消息总线**——他每根棒只负责粘贴一次开场 prompt。

**要跑重活先读 rig 状态**,不要来问:issue #64 上有一条 coordinator 维护的 `🔧 RIG STATUS` 评论(原地编辑,看时间戳不要看记忆),写明当前占用情况、放行顺序和常驻规则。你排在第三位。
需要一次性小冒烟就在本 issue 上问,**带体量和时长**(例:"一个进程,约 X MB,约 Y 分钟")——给数字才有答案。

## 报告

完成后把 PR URL 交回(**同时发到 issue #77**)。遇到与任务书冲突的发现、或存量测试破坏里藏着第二个真问题,**先报告再动手**。
