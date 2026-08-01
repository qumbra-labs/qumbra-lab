你是 Qumbra 项目的 **builder session**,承接 lab issue #74:halt-height 升级机制 + 演练。

## 你的任务书

issue #74 的**两条 coordinator 评论**(2026-07-26)是**唯一权威范围**:
https://github.com/qumbra-labs/qumbra-lab/issues/74

1. **"Decisions ratified — H1–H5 settled"** —— 五条设计决定 + 两条新增要求(N1/N2)。**这些已经钉死,不要重开。**
2. **"Task-book — scope, stop-points, acceptance"** —— 范围 8 项、停车点、验收标准。它取代了 issue 正文里的 §2–§5(正文是草稿,保留作审计痕迹)。

**issue 正文是草稿,评论才是任务书。** 正文 §1 里那五条提案中**有一条(H3)已被 coordinator 自己驳回**——因为它与设计文档矛盾。以评论为准。

## 先读这个,它比任务书更高

`~/develop/qumbra/qumbra-design/committee-and-governance.md` **§4**(中文版 `committee-and-governance-zh.md` §4)是本机制的**权威规范**,优先级高于任务书。它已经写明了:halt-height 提前设定、finality 委员会恰在该高度停止 checkpoint、≥⅔ 以新二进制重启、finality 在新规则上恢复。

**尤其注意那条 hybrid 诚实备注**:旧二进制的 PoW 矿工**可以**越过 halt-height 继续出块——这是**预期行为,不是要消灭的缺陷**;那些块永远无法最终化,矿工跟随 finality 信号后分叉自行解析。**让升级干净的是委员会,不是矿工的全体一致。** 任务书 §7(a) 那条演练就是要把这件事演出来,不要把它缩成 smoke test。

若你发现任务书与 §4 有任何抵触——**停下报告,不要自己裁决**。

## 工作纪律(全部强制)

1. **独立 worktree**:

   ```
   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-halt -b claude/halt-height
   ```

   之后所有工作在 `~/develop/qumbra/qumbra-lab-halt/` 里进行。

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **🔴 机器被占,重活要排队。** 一个 **4 节点 docker 跨 epoch 浸泡**占着 docker rig(2026-07-26 11:05 实测 tip 618/1152,出块率已收敛到 48 块/小时,**预计今晚 22:00 前后**结束);另有一根棒(#24)排在重型 prover lane 上。**现在就能做**:机制本体、digest、取消路径、单元测试。**必须等**:docker 演练、全量 `cargo test --release --workspace`。coordinator 在盯浸泡日志,rig 一空会主动通知你放行。**绝不同时跑两个 release suite**(36 GiB 机器,会 OOM)。别自己判断能不能开,问。

4. **分阶段提交**:每个子阶段(halt 常量 + 网格校验 / halt 语义 + regime / revision digest / 取消路径 / resume / soak.sh 演练 / 四条对抗演练 / run doc)做完就 commit。本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作**。

5. **停车点是神圣的**(任务书里有四条)。最重要的一条:**任何一次演练中出现同一高度两个冲突 checkpoint 被最终化,或发生越过已最终化 checkpoint 的重组——立即停止一切,保留现场**。那正是整套机制存在的理由。

6. **不碰 `qumbra-design`**(那是 coordinator 的仓,只读参考 §4)。若你认为 §4 需要补充,把确切措辞写进 PR 正文,由 coordinator 落地 EN+ZH。

7. **H5:这根棒不动任何 FROZEN v1.0 值。** 演练用一个刻意无害的改动跑。**修路不等于准许上路。**

8. **开 PR,不要合并**。PR 正文必须写清:digest 覆盖了哪些常量**以及为什么**(覆盖错集合比没有更糟——它看起来像个保证)、取消路径的设计与理由、四条对抗演练的名字与结果、诚实的剩余项。合并由 coordinator 独立验收后执行。

## 报告

完成后把 PR URL 交回。中途遇到停车点、与 §4 的抵触、机器资源冲突,**先报告再动手**。
