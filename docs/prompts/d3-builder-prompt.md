你是 Qumbra 项目的 **builder session**,承接 lab issue #24 的 **D3**:leaf F0 digest input binding。

## 权威来源有两个,顺序别搞反

1. **`docs/issue24-findings.md` 的 §"D3 spec (the remaining leaf binding)"** —— **这是设计**,由做完 D0–D2 的 builder 从机制内部写的。**先读它,照它做。**
2. **issue #24 上标题为 "Task-book — D3: leaf F0 digest input binding (2026-07-26)" 的 coordinator 评论** —— 只补 spec 写作时(PR #30 时代)不可能知道的东西:`main` 当前状态、边界、验收标准。

https://github.com/qumbra-labs/qumbra-lab/issues/24

**两者冲突时:技术设计以 findings 文档为准,范围与验收以 coordinator 评论为准。**

## ⚠️ issue 正文是过期的,别读它做判断

正文顶部有过期警示块。**D0/D1/D2 早已合并(PR #30,2026-07-22)**,正文里那套"路径 1 vs 路径 2 二选一"**不是待决问题**。今天早些时候有一份基于该过期正文写的任务书,已被 coordinator **全文撤回**(见 `docs/issue24-taskbook-conflict.md` 与撤回评论)。**D3 是 #24 唯一还开着的项。**

## 这根棒的前提,和被撤回那份相反

**你被期望去改 leaf public-value 布局,以及随之级联的 interior 布局。** 那正是 D3 本身。这是唯一允许打破 narrow-byte-identical 不变量的地方。**不要为此停车报告**——按任务书要求把整条级联链 before→after 精确算出来、写进 PR 正文即可。

行号提示:findings 文档的行号是 PR #30 时代的,已漂移。coordinator 评论里有一张今天核过的对照表(`WordBind :587`、`shape_mosaic :629`、`f2dig :1152/:1379/:2804`、`OREG :825`、`tamper_coverage :6673` 等),照那张表找。

## 唯一能终结这根棒的数字

放大 leaf public surface 会放大 interior。决定的 interior lane 是 **b2/q86**,当前实测 **20.2–22.5 GB / 32 GB 包线**(约 30–37% 余量,已含 msh)。有余量——但**这次成本是真未知,必须实测,不许估算**。

**停车点:若 D3 之后 interior 在 b2/q86 上超出 32 GB 包线,或余量 < 10% —— 停下,带着测量数据报告。** 拿聚合 lane 的余量去换这条绑定,是 lane 级决定(包线的意义是去中心化:必须装进真正的 32 GB 机器,而不是靠内存压缩塞进 36 GiB 台机),归 coordinator 拍,不是 builder 拍。

## 工作纪律(全部强制)

1. **独立 worktree**:

   ```
   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-d3 -b claude/i24-d3-leaf-digest
   ```

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **🔴 机器被占,重活排队。** 一个 4 节点 docker 跨 epoch 浸泡占着 rig 到**今晚约 22:00**,另有 #74 halt-height 棒在飞。**现在能做**:设计、实现、定向单测。**必须等**:`m4gate` / b4 interior bench、全量 `cargo test --release --workspace`。**开任何重活前问 coordinator**,它盯着浸泡、会按顺序放行。绝不同时跑两个 release suite。

4. **分阶段提交**。本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作**。

5. **三个坑**(findings 文档 §Traps,会咬人):`deg ≤ 3` 是硬线(`constraint_degree_within_budget`),不是文档里写的 deg 5;Monty 因子用 `c(rr.as_canonical_u32())`,**永远不要** `cf(rr)`;区域外的行必须在 fill 里把新列清零,否则 `assert_bool`/one-hot 会挂。

6. **不动任何 FROZEN v1.0 常量。** 你改的是 public-value 数量,不是任何 FRI 参数。若发现必须动,**停下报告**。leaf 证明尺寸会变大,这是**可接受的**(rung-1 聚合按设计是 post-launch 里程碑)——测量它、写清楚,别为了压尺寸牺牲绑定。

7. **不碰 `qumbra-design`**。`aggregation-rung1.md` 落地后要加 measured-update,**把你想要的确切措辞写进 PR 正文**由 coordinator 落地。**措辞要格外小心**:上一个替这个 issue 起草 §2 文字的人,差点把一句假话写进权威规范。

8. **如果 XOR-mode 消息恢复需要 OREG/pbit/obit 寄存器文件没暴露的 bit 级状态——停下报告,不要自己新建一套寄存器文件。** 那是值得一个决定的设计变更,不是实现细节。

9. **开 PR,不要合并**。PR 正文必须有:完整的 before→after 级联表(含 `merge_perms()` 的算式)、SAT→UNSAT 翻转证据、f0dig 与原生重算摘要一致的测试名、重测的 leaf 尺寸与 interior 峰值内存及对 32 GB 的余量、诚实剩余项。

## 报告

完成后把 PR URL 交回。遇到停车点、机器冲突、或与 findings 文档的抵触,**先报告再动手**。
