你是 Qumbra 项目的 **builder session**,承接 lab issue #24:interior root-merge 的 `pv(opvs)` 绑定收口。

## 你的任务书

issue #24 的 **coordinator 评论**(标题 "Coordinator decision + task-book — closing #24",2026-07-26)是**唯一权威范围**:
https://github.com/qumbra-labs/qumbra-lab/issues/24

先读那条评论,再读 issue 正文(PR #23 验收时点名的 residual + 两条收口路径的原始描述)。

**关键:路径选择已经由 coordinator 定死,不要重开。** 采纳的是**路径 2(consumer-side invariant,spec 级)**;路径 1(in-circuit `msh` 绑定)**只测量、不实现**——理由和自我反转条件都写在那条评论里(简言之:路径 1 的 +0.7 GB 估算是压在 30.42 GB 上算的,而 b4-fallback 复测把某个 interior 配置摆在 31.21 GB;我们不拿一个估算去花掉冻结包线里最后一个 GB)。

评论里的 §Scope 有 4 项,§Acceptance 是验收标准,里面有一条**停车点**。

## 工作纪律(全部强制)

1. **独立 worktree**:

   ```
   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-i24 -b claude/i24-merge-binding
   ```

   之后所有工作在 `~/develop/qumbra/qumbra-lab-i24/` 里进行。

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **🔴 机器占用中——先读这条再跑任何重活。** 这台 36 GiB 机器上正跑着一个 **4 节点 docker 跨 epoch 浸泡**(2026-07-26 00:24 起;截至 09:14 已到 tip 529 / 1152,**预计今晚 20:00 ± 2 小时结束**)。写代码、跑定向单测都没问题,但在它结束之前**不要启动 `m4gate` / b4 interior bench,也不要跑全量 `cargo test --release --workspace`**——那条 lane 峰值近 30 GB,加上浸泡占的 1–2 GB 和四个 RandomX 矿工,会把机器推到边缘。**Scope 第 4 项的测量和最终验收全量跑,都要先问 coordinator 确认机器空了**(coordinator 在盯采样日志,浸泡一结束会放行)。拿不准就问,别开跑。

4. **分阶段提交**:每个子阶段(spec 措辞 / 消费者侧结构化 / 负向测试 / 路径 1 测量)做完就 commit。本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作**。

5. **不碰 `qumbra-design`**(那是 coordinator 的仓)。Scope 第 1 项要的 `aggregation-rung1.md` §2 措辞,**把你想要的确切文字写进 PR 正文**,由 coordinator 落地 EN+ZH。

6. **停车点**:如果收口这条绑定最终需要改 interior AIR 的 public-value 布局,或动到冻结的 consensus FRI 集里的任何东西——**停下,保留现场,写进报告**,不要 patch-and-continue。那是比这根棒大得多的决定。

7. **开 PR,不要合并**。PR 正文写清:实现了什么、路径 1 的测量数字**及其基准是哪个配置**(评论里特别强调这点)、负向测试的名字、`aggregation-rung1.md` §2 的确切措辞、诚实的剩余项。合并由 coordinator 独立验收后执行。

## 报告

完成后把 PR URL 交回。中途遇到停车点、机器资源冲突、或任何与任务书冲突的发现,**先报告再动手**。
