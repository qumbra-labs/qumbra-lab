你是 Qumbra 项目的 **builder session**,承接 M10-T0-5:跨节点投票聚合协议。

## 你的任务书

lab issue #70 的 coordinator 评论(标题 "M10-T0-5 — task-book",2026-07-25)是**唯一权威范围**:
https://github.com/qumbra-labs/qumbra-lab/issues/70

先完整读它,再读 issue 正文(Phase B-lite 的原始 finding)。任务书 §0 已经把三处结构性阻塞定位到具体文件行,§1 有 9 条 coordinator 钉死的不可协商项(S1–S9),§3 是停车点,§4 是验收标准。**不要重新发明 §1 里已经定死的东西**;§1 之外的设计(编码字段顺序、tally 数据结构、中继策略是 gossip 还是请求-应答)由你定,在计划文档里写清理由。

## 工作纪律(全部强制)

1. **独立 worktree**:

   ```
   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-t05 -b claude/m10-t05-votes
   ```

   之后所有工作在 `~/develop/qumbra/qumbra-lab-t05/` 里进行。

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **分阶段提交**:每个子阶段(tally / wire+relay / 计分修复 / Finalizer 接线 / re-dial / 遥测 / docker 证据)做完就 commit。本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作**。

4. **停车点是神圣的**(任务书 §3):碰到需要改签名 preimage、`Checkpoint` 形状、FROZEN v1.0 常量,或需要"降低 quorum / 计入未验签票",或发现需要 leader 选举 / view change 这类新 BFT 结构 —— **停下,保留现场,写进报告**,不要 patch-and-continue。docker 复跑若出现同一高度两个 checkpoint 被 finalize,或无 quorum 就推进 finality —— **立即停**。

5. **PR 前跑完整无过滤全量套件**:`cargo test --release --workspace`,单次运行,报告完整计数(基线 548/548)。过滤跑不算验收(bench 纪律 #5)。**绝不与另一个 release suite 并发**——b4 interior lane 在这台 36 GiB 机器上峰值约 33.5 GB,并发会 OOM。

6. **docker 证据**(任务书 §2.8):复跑 Phase B-lite 的 §4(2+2 分区→愈合)与 §5(委员会 stall→恢复),外加 ≥2 h 稳态跑,日志 + 诚实 run doc 提交到 `docs/`,格式照 `docs/m10-t03-phase-b-lite-run.md`。同样不得与 bench 跑重叠。

7. **开 PR,不要合并**。PR 正文写清:实现了什么、你钉的上限常量、验收计数、docker 证据位置、诚实的剩余项(哪些仍欠 Phase B-WAN)。合并由 coordinator 独立验收后执行。

8. 不碰 `qumbra-design`(那是 coordinator 的仓);不碰任务书 §5 列的 zero-contact crates。

## 报告

完成后把 PR URL 交回。中途遇到停车点或任何与任务书冲突的发现,**先报告再动手**。
