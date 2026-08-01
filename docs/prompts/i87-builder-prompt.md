# Builder prompt — issue #87:委员会诊断与结构化指标

粘贴给一个新的 T-build 会话。任务书是 issue 本身,不要另找。

---

## 你的任务书

https://github.com/qumbra-labs/qumbra-lab/issues/87

它是从 T0 四节点 WAN soak 的实测数据里长出来的,不是凭空提的。开工前把 issue 正文里那组数字读完——它们决定了这根棒的形状。

## 这根棒最容易犯的错

**把它当成"加一个 `/metrics` 端点"。** 那是它较不值钱的一半。

值钱的那一半是 **round 级诊断**:那个网 14.1–15.4 % 的采样处于 `Degraded`、`stall` 峰值到 42(阈值 16),而**没有任何人能说出为什么丢了 checkpoint**——整整 48 小时里节点只产出十行非 telemetry 日志,全在启动时。没有 round 号、没有票数、没有超时原因、没有缺席名单。

所以判据很硬:**如果你的成果只是把 `TELEMETRY` 行里已经打印的那些 gauge 换个格式导出一遍,这根棒就白跑了。** 它必须能回答"这一轮为什么没成"。

顺带一条会救你时间的:**打印出来的 gauge 无法还原成直方图。** 信息是在打印那一刻被销毁的,不是在解析那一刻。所以 counter 和 histogram 要在源头就是 counter 和 histogram。

## 一个真的开着的问题,别猜答案

**拉(`/metrics` + Prometheus scrape)还是推(节点主动上报)?**

coordinator 的立场在 `qumbra-design/observability-and-evidence.md` §5,**并且刻意没有把这个问题在任务书里盖死**——那份文档采纳时明确写了"采纳本文不预先决定拉/推"。

告诉你这件事是为了不让你重复劳动,不是要你附和。要求是:

- **同意就用你自己的论据说一遍**,不要引用了事;
- **不同意就说不同意,并给理由**——**一个有依据的反对,对我比一次附和有价值得多。**

这个选择会连带决定部署形状(拉需要在四台 SG 上开入站规则,推不需要),所以论据里要包含这一层。

## 🔴 三条钉死项

**一、不动 `DEGRADED_MODE_LAG_BLOCKS`,不动 FROZEN v1.0 集合里的任何常量。** 这根棒的产出是用来*支撑*那个判断的证据,不是那个判断本身。改 FROZEN 要走 halt-height + 修订文档,是完全独立的一件事。**在这根棒里顺手调一下"看起来更合理的阈值"= 直接停车。**

**二、现有那一行 `TELEMETRY` 的格式不许改。** 外部有消费者(含 `dialable=<n>/<known>`、一个正在跑的 T0 采样器,以及**一份已经封存合并的证据包** [PR #93](https://github.com/qumbra-labs/qumbra-lab/pull/93))。**新增字段可以,改动或重排现有字段不行。**

**三、不碰共识层**,不新增 codepoint,不改任何载荷。

## 不要部署

这根棒的产物**不由你上线**。48 h 连续性证据已于 2026-07-28 封存([PR #93](https://github.com/qumbra-labs/qumbra-lab/pull/93)),但那四台仍在跑,等的是一次**统一重部**——由 coordinator 与 T-ops 执行,一次性携带 #79 + #82 + #86 + 你这个。**在 lab 网里验,不要碰那四台,也不要请求碰。**

## 工作纪律(全部强制)

1. **独立 worktree**:

   cd ~/develop/qumbra/qumbra-lab && git worktree add ../qumbra-lab-i87 -b claude/i87-diagnostics

2. **REPEAT-GOTCHA(本项目已有两次实测事故)**:曾有 builder subagent 误改**主工作树**。**每一批编辑前先确认 cwd 是你自己的 worktree**;派任何 subagent 都要把这条警告原样转发进它的 prompt。

3. **重活要问。** 定向测试随便跑(`-p qlab-node` 之类);**全量 `cargo test --release --workspace` 开跑前先问 coordinator**——rig 是共享的,并发两个 release 套件会 OOM。**[issue #91](https://github.com/qumbra-labs/qumbra-lab/issues/91)(peer hardening)可能同时在跑,它和你抢同一台机器。**

4. **分阶段提交。** 本项目 builder 多次在 usage limit 中途被打断——**未提交的大改动 = 丢失的工作。**

5. **停车点**:需要改 `TELEMETRY` 现有字段、需要新 codepoint 或改载荷、需要碰共识层、或者你认为必须调整某个 FROZEN 常量才能做下去。**停下报告,不要重构了再说。**

6. **不碰 `qumbra-design`**。若你认为设计文档该记某条,把确切措辞写进 PR 正文,由 coordinator 落地。

## 一条会让你省事的先例

本项目刚吃过两次"数字带着口径,而口径不跟着数据长"的亏(D3 差点被记上别人的 +51 KB;一张 stall 表停在了 264 个采样而运行有 277 个)。

你会产出计数和分布。**把口径和数字写在一起**——每个数是在什么窗口、什么节点、多少采样上得到的。这条现在写进去是一行字,事后补是一次考古。

## 沟通走 GitHub,不走人(operating-model §3.3,必带)

**不要指望有人替你转述。** 向 coordinator 提问之后、以及动手做被提问的那部分之前,**先去 GitHub 查回复**:

    gh issue view 87 --json comments --jq '.comments[-3:] | .[].body'
    gh pr view <你的 PR 号> --comments

问题也发在那里,不要只写在自己的报告里——**写在报告里的问题没有人会看见。**

## 开 PR,不要合并

合并是 coordinator 的事,在独立验收之后。

## 报告

PR 正文写清:

- **拉还是推,你的选择和理由**(以及你是否同意 coordinator 的立场);
- round 级诊断**具体记了哪些字段**,以及判据——*仅凭这些字段能否事后区分"超时"与"票不够"*;
- 诊断是常开还是开关后面,若常开给出 75 s 节奏下的写入量估算(这要长期跑在 2 vCPU 机器上);
- **缺席成员点不点名**,以及理由;
- 每条验收对应的测试名;
- 诚实剩余项。
