# CI 套件跑在哪里，以及它花多少钱

**状态：一半已定，一半未定。** *（2026-08-02 修订：按 Larry 的提议补入选项 F —— EC2 on-demand 叠加
Savings Plan —— 第一版遗漏了它，而它取代 spot 成为值得算账的那个 AWS 选项。这次修订同时暴露出：T0 机队
自己的 on-demand 成本从来没有被测量过。同日再次修订：评估了选项 G —— EKS，runner 跑在 pod 里 —— 其
前提在写作过程中被 Larry 改变，因而它从"不建议"变为"有条件"；而评估它的过程掀出了一个对所有选项都适用
的规格杠杆。）* 架构已经定了，也不会变。**"跑在哪里"从来没有被决定过** —— 它是一次
$2 实验默认下来的，而那个月份现在是 $9.31 —— 预算是 Larry 的判断（R3）。这份文档存在，是因为那个默认
从来没有书面记录，而这一点在 2026-08-02 第一次打开账单页时才被发现。

English: [`ci-runner-cost-decision.md`](./ci-runner-cost-decision.md) —— 技术细节以英文版为准。

---

## 1. 今天实际在跑的是什么

`.github/workflows/acceptance-graviton.yml` 在**自托管 AWS Graviton rig** 上运行
`cargo test --release --workspace --locked -- --test-threads=1`；当 `crates/**`、`Cargo.toml`
或 `Cargo.lock` 有改动时，由 `verify-graviton` 标签触发，另外保留 `workflow_dispatch`。
托管的 start/stop job 只唤醒队列所需的持久实例，并在 lane 清空后停机；suite job 本身使用实例的热缓存。

这就是 `CLAUDE.md` §5 记录的验收标准。原 GitHub 托管比较 lane
`.github/workflows/suite-arm64.yml` 在比较任务完成后于 2026-08-21 退役；下文带日期的测量和退役记录
仍是历史证据，不是当前拓扑。

## 2. 已经定了的，不在讨论范围

**arm64，不是 x64**（`PR #186`）。rig 是 M3，四台 T0 主机是 AWS `t4g.small` Graviton，GHCR 镜像
是 arm64 构建。`randomx-rs` 在编译期构建一个 C++ 库，而 aarch64 在那里真的出过问题 ——
`M10-T0-3 Phase B-lite` 记录着 *"RandomX-on-Linux-aarch64 build RESOLVED"*。**x64 上的绿色验证的
是一个这个项目从未部署、也永远不会部署的架构。**

无论 runner 放在哪里，这一条都成立。下面任何给不出 arm64 的方案，在成本进入讨论之前就已经出局。

## 3. 从来没有被决定过的

**没有人把 GitHub larger runner 和 EC2 spot 比较过，也没有和任何其他方案比较过。**

`PR #186` 提议的是**一次手动运行**回答四个问题，其中成本那一项的措辞是 *"(3) × 每分钟费率"*，而赌注
写的是 *"如果不行，这个文件就删掉，我们花了约 $2 买了个答案。"* 在 $2 这个量级上，做一次选型比较比实验
本身还贵。**当时那是对的判断。** 只是当这个 workflow 从只有 `workflow_dispatch`（`#186`）变成每次 PR
推送都触发（`#191`）时，那份记录没有被重新检视。

**所以"用 GitHub larger runner"不是这个项目做过的决定，而是它从一次成功的实验里继承下来的默认值。**

## 4. 数字，以及它们是怎么来的

2026-08-02 08:53 +0800 从组织账单页和 `gh run list` 推导。**账单页只给一个数字 —— `$20.00` 预算里
`$9.31 spent`，`Stop usage: Yes`。** 下面其余全部由它除出来，并且标注清楚。

| | 值 | 怎么来的 |
|---|---|---|
| suite 运行次数，2026-08-01 | **19** | `gh run list --workflow=suite-arm64.yml` |
| suite 分钟数，2026-08-01 | **671** | `updatedAt − createdAt` 求和 |
| 单次均值 | **35.3 分钟** | 671 / 19 |
| 同期 prefilter/check 运行 | 44 | `gh run list --workflow=prefilter.yml` |
| **本月已花** | **$9.31** | 账单页，实测 |
| **反推费率** | **≈ $0.0139/分钟** | 9.31 / 671 —— 这是 suite 费率的**上界**，因为那 44 次 prefilter 在 $9.31 里面、在 671 分钟外面 |
| **单次 suite 成本** | **≈ $0.49** | 费率 × 35.3 |
| 硬停之前剩余 | **$10.69** | 20 − 9.31 |
| **还能跑几次 suite** | **≈ 22** | 10.69 / 0.49 |

**这修正了一个更早的估计。** `PR #191` 记录的是 *"约 $0.7/次，对着 $20/月的上限"*。实测是 **$0.49**，
低约 30%。$0.7 是测量之前的估计，而上面的算术是**第一次**用真实花费除以真实分钟数。

### 要紧的那一段

**19 次全部发生在 2026-08-01。** 这个月还剩 29 天，预算还剩约 22 次 suite。按观察到的速率，预算会在
大约再一个工作日内硬停，而 `Stop usage: Yes` 意味着 CI **停掉** —— 它不会超支后再计费。

## 5. 钱花在哪，而那里不是它看起来的地方

2026-08-01 的运行，按触发来源：

```
4  workflow_dispatch  main
3  pull_request  claude/i133-d3-tombstone-restart
3  pull_request  claude/i130b-body-refusal-counter
2  pull_request  claude/i198-possession
2  pull_request  claude/i188-serve-committed-discovery
2  pull_request  claude/i180-sigkill-replay
1  pull_request  claude/i204-ask-what-is-finalized
1  pull_request  claude/i200-state-tip-mine-on-exhaustion
1  pull_request  claude/i187-fid-split-expression
```

🔴 **好几个 PR 跑了两三次 suite，而协调者只读其中一次。**

验证程序是**同树比较**：协调者把 `main` 合进 PR、推那棵合并树、在**那棵树上**把 CI 的数字和 rig 的
数字对照。builder 中间某次推送触发的运行，是一棵没有人会合并的树上的数字。它不会被读、不会被引进验收
评论、也不会进入那份一致性台账。

**大约一半的花费买的是没有人看的数字。**

`cancel-in-progress: true`（`PR #191`）在有更新的提交时已经会截断被取代的那次运行 —— 这就是为什么有
三次显示为 `cancelled` —— 但**一次被取消的运行仍然烧掉了它已经跑掉的分钟**，那三次加起来约 81 分钟。

## 6. CI 到底是干什么的 —— 在砍任何东西之前先说清楚

**不是为了快，也不是为了对正确性再来一个意见。是为了 R1。**

> *产生证据的会话，不能是对它作出裁决的会话。*

今天协调者在自己的 rig 上跑套件，然后对结果作出裁决。CI 在同一棵树上独立跑，是当前配置里**唯一**让证据
独立性成为**结构性的**而不是**协调者自律**的东西。`PR #186` 把这一点直说了，作为考虑让 CI 成为标准的
理由。

还有第二个、更小的价值：runner 是 **Linux/arm64**，rig 是 **macOS/arm64**。对于一个本月的缺陷集中在
持久化、套接字和进程重启的代码库，多一个操作系统不是舍入误差。

### 诚实的台账

**七次同树比较。七次一致。零次分歧。**

（1030、1031、1045、1046、1051、1056、1060 —— 之后还有 `PR #202` 的 1074。）

**这个程序到今天为止还没有抓到过一个缺陷。** 它是便宜的保险，而现在保费可见了 —— 这个事实应该摆在决定
花多少钱的桌面上。`PR #191` 预先登记了一次分歧意味着什么 —— *"那次分歧比整个实验都值钱"* —— 而它没有
发生过。

## 7. 选项

评估维度：arm64（强制，§2）、R1 独立性（§6）、成本、以及**运行它本身的代价**。

### A. 保持 GitHub larger runner，提高预算

结构上什么都不变。**R3：花钱需要 Larry，每一次，明确地。** 协调者不动它，也没有动过。

按实测 $0.49/次，当前**程序**（不是当前**速率**）一个月大约是每个已合并 PR 一次运行。速率问题在 §5，
不在托管方式。

### B. 保持 runner，修触发条件 —— 免费、可逆、单文件

只在协调者真正会读的那棵树上触发套件。此方案内部还有若干做法：协调者推合并树时打一个标签、用
`merge_group`、或把 `pull_request` 限制为只响应协调者那次推送的 `synchronize` 事件。

**砍掉大约一半花费，且不损失任何当前在使用的信息** —— 因为当前在使用的信息就是每个 PR 一次，即合并树
那一次，而这个做法保留的正是它。

**这不需要预算决定，也不需要 Larry。** 它是对 `suite-arm64.yml` 的单文件、可逆改动；而且一个纯文档或
纯 workflow 的 PR **不会触发套件**（`PR #191` 加的 `paths` 过滤），所以提出它本身是免费的。

**2026-08-02 已实施：** `pull_request: types: [labeled]`，外加一个 job 级 `if` 检查标签名是
`verify`（`labeled` 事件对**任何**标签都触发，所以没有名字检查的话，加一个无关标签就会花掉 34 分钟的
付费时间）。`workflow_dispatch` 有意绕过这个门 —— 手动路径本身已经是一次明确的行为。

🔴 **它造出来的次序，而且是这个项目反复付账的那个形状：先推合并树，再打标签。** 先打标签会让套件跑在
合并之前的 head 上，返回一个**看起来像**同树结果、而实际不是的数字。它对着 PR 自己的 base 照样能对上
账，所以不会有任何东西报警。重新打标签会在当前 head 上重跑，`cancel-in-progress` 会杀掉过期那次。

### C. AWS EC2 Graviton spot，self-hosted runner

单位分钟成本便宜一大截 —— `t4g`/`c7g` 一类的 spot 大约是 GitHub larger runner 的五分之一到十分之一，
而这个项目已经在跑 Graviton 主机、也已经有 Terraform（`qumbra-deploy/terraform/`）。**arm64 要求原生
满足。**

表格里看不到的代价：

- **多一台要维护的机器**，和一个要保活的 runner 注册。四台 T0 主机已经是一个运维面；这会加上第五台，
  而且它不属于那张网。
- **35 分钟串行套件跑到一半被 spot 回收。** 两分钟的驱逐通知，对着一个无法续跑的运行，意味着这次跑丢
  了、要重跑，而重跑同样可能被打断。套件的 `--test-threads=1` 没有商量余地（`CLAUDE.md` §5），所以
  不能靠并行缩短。
- **它削弱 CI 唯一存在的理由。** 一台由协调者开通、配置、并且能够触达的 self-hosted runner，比 GitHub
  托管的那台**离 rig 更近**。R1 的独立性有一部分是**组织性的** —— 一台本会话在运行途中碰不到的 runner，
  是比一台由本会话管理的 runner 更强的证人。
- **self-hosted runner 执行 pull-request 代码有已知的安全形状。** 在这里被削弱了 —— 私有仓库、一个人、
  agent 写的分支 —— 但"被削弱"不等于"不存在"，而且这应该被写下来，而不是被撞见。

**以上没有一条否决 C。** 它说的是 C 的真实代价是运维性和结构性的，不是每分钟单价 —— 而一次纯按单价做的
比较会有误导性。

**部分被下面的 F 取代**：如果离开 GitHub 的理由是成本，那么 on-demand 加启停能拿到大部分节省而没有回收
这个失败模式，所以 **C 现在是两个 AWS 选项里较弱的那个**，保留在这里只是因为它的每分钟单价确实更低。

### F. AWS EC2 Graviton **on-demand**，围绕每次运行启停 —— 可选叠加 Savings Plan

**Larry 在 2026-08-02 提出，本文档第一版遗漏了它。** 它不是 C 的变体 —— 它直接消掉了 C 唯一那个
**技术性**反对理由。

**spot 的回收在这里是致命的，on-demand 没有这个失败模式。** 两分钟的驱逐通知，对着一个 35 分钟、
无法续跑的串行运行，意味着这次跑丢了，而重跑同样会被打断。`--test-threads=1` 没有商量余地
（`CLAUDE.md` §5），所以不能靠并行把时间缩短到风险窗口以下。on-demand 根本不存在这个问题。

**实例必须在空闲时停掉，而这就是全部的成本模型。** EC2 运行时按秒计费。套件大约每天跑一小时；一台一直
开着的机器一个月要为 30 小时的活计费 720 小时。所以 F 实际上是 **on-demand 加启停编排**，而**被买下的
是那个编排，不是那台实例**。

**Savings Plan 在哪里有用、在哪里没用 —— 这一段值得写准。** Compute Savings Plan 承诺的是一个固定的
**每小时美元数、持续地**，为期一年或三年，换取折扣。**对一个利用率约 4% 的工作负载，这个工具不合适**：
按 CI 峰值买，就是为每天约 23 个空闲小时付钱；买得足够小以避免这一点，折扣就只覆盖很薄的一片。
**单为 CI 买一份 Savings Plan，很可能花掉的比省下的多。**

**但这个项目已经有一个持续运行的 on-demand 机队，而且没有人给它算过账。** 四台 T0 主机是
`t4g.small`、on-demand、分布在四个区域（`us-east-1`、`eu-west-1`、`ap-southeast-1`、
`ap-northeast-1`），而 `terraform/` 里**没有任何 `spot` 或 `market_options` 配置** —— 所以四台全是
完整 on-demand。它们从 2026-07-26 15:43 起连续运行：**每台约 161 小时，合计约 646 实例小时，且仍在
运行。**

🔴 **那个机队才是 Savings Plan 真正适配的工作负载，而且它几乎肯定是一个比本文档所讨论的整个 CI 问题
更大的开支项。** 四台小实例在四个区域 24/7 运行，按标价大约是每月几十美元的量级，而 CI 预算是
**$20** —— 并且 Compute Savings Plan **跨实例族、跨区域**生效，所以一份按 T0 机队规模买的承诺，会顺带
把一台 CI 实例的偶发小时数也吸收进去。

**上述美元数字的标尺：一个都不是实测。** 本文档 §4 的数字来自 GitHub 账单页除以运行时长。**AWS 那一侧
完全没有被读过** —— 没有 Cost Explorer 数字，没有账单，没有查过任何区域单价。上面的实例类型、数量、
区域和运行时长**是**从 `terraform/` 和部署记录核实过的；**美元**部分是标价推理，在买任何东西之前必须
对着真实 AWS 账单确认。**R3 全力适用：这是花钱，归 Larry，每一次。**

**F 仍然要付的、和 C 一样的代价：** 多一台不属于那张网的机器要维护、一个要保活的 runner 注册、
self-hosted runner 执行 PR 代码的那个安全形状、以及 R1 的稀释 —— 一台本会话开通并且能触达的 runner，
是比一台碰不到的更弱的证人。

### G. AWS EKS，runner 跑在 pod 里（actions-runner-controller）

**Larry 在 2026-08-02 提出。** 按同样四个维度评估，而结论取决于**这个工作负载究竟是什么**，不是 EKS 有
什么问题。

**它真正能买到的东西。** `actions-runner-controller` 提供**一次性 runner** —— 每个 job 一个全新
pod，跑完销毁 —— 这比 F 那种长期存在的 self-hosted runner 在安全姿态上好得多，因为 §7C/§7F 里
"self-hosted runner 执行 PR 代码"那个形状，大半是一个**持久化**问题。它是声明式的，节点容量能在 job 之
间缩到零，而且在每小时跑几百个 job 的组织里，这就是标准答案。

**为什么在这里不合适，而且差得不近。** **EKS 控制面持续计费且无法缩到零** —— 按标价大约每月 $70–75，
**在任何节点跑任何一个测试之前**。那大约是**本文档整个 $20 CI 预算的 3.5 倍**，服务的是**一天一两次、
一个 job、完全不需要任何调度决策**的负载。

Kubernetes 解决的是多租户、装箱和机队编排。**这个负载有一个租户、一个 pod、没有任何要装的箱。** 套件
是单机上的一个串行进程；**没有调度问题留给调度器解决。**

**而且它加的运维面比 F 大，不是小。** 一个集群、ARC 及其 webhook、node group 或 Karpenter、IRSA，外加
EKS 自己强制的 Kubernetes 版本升级 —— 对比 F 的"一台实例，开、关"。§7C 和 §7F 的 R1 反对理由原样适
用：一个本会话开通并且能触达的集群，是比一个碰不到的 runner 更弱的证人。

**G 在什么情况下会变成对的：** 如果 CI 量长到每小时很多 job、如果多个仓库共用它、或者**如果集群本来就
因为别的原因存在**。**以上都不成立**，而第一条正是 §7B 刚刚反方向走过的路。

**一次性 runner 这个好处是可以拆出来的，而这才是这个问题里有用的部分。** F 不需要集群也能拿到它的大
部分 —— 用 launch template 每次运行起一台、跑完销毁，或者跑一个 **ECS/Fargate** 容器任务，后者**完全
没有控制面费用**并且支持 arm64。如果考虑 G 的理由是**一次性**而不是 **Kubernetes**，那 Fargate 是更
便宜的买法，而且它属于 F 的比较范围，不该单列成一个选项。

**不建议 —— 前提是这个集群为 CI 而存在。** 不是因为 EKS 错，而是因为光是那个固定控制面成本就超过了本
文档所讨论的全部预算，而这个负载没有调度问题。

#### 🔴 这个前提在本节写作过程中就变了

Larry，2026-08-02：*"我可以把 aws profile default 里面的好多 ec2 拿掉，换到 eks 里面跑。"*

**如果集群本来就要存在，它的控制面费用就不该算在 CI 头上，上面那条主要否决理由随之消失。** 这在结构上
和 §7F 关于 Savings Plan 的结论是同一个论证：固定成本由**持续性**负载来justify，而 CI 作为副产品搭
车，不必自己去论证它。**G 没有被否决；上面评估的那个版本，只是不是现在摆在桌上的那个版本。**

那么 G 会是什么，诚实地和 F 比：

| | F（on-demand + 启停） | G（已存在的集群 + ARC） |
|---|---|---|
| 应算在 CI 头上的控制面成本 | 无 | **在新前提下同样无** |
| runner 生命周期 | 长期实例，或每次运行的 launch template | **每个 job 一个一次性 pod —— 更好** |
| **CI 新增**的运维面 | 一台实例 + 启停 | **在一个已经在运维的集群上装一个 ARC** |
| R1 独立性 | 被稀释（§7C） | **同样被稀释，不好不坏** |

**在这个前提下 G 变成更强的选项**，因为一次性 runner 是 self-hosted 安全形状里"持久化"那一半的正确答
案，而在共享集群上它几乎不额外花钱。

**决定之前需要什么，这不是意见问题：** 那个 profile 里到底有什么、每台在干什么、有没有有状态的。
**本文档无法评估一次它没有看见的整合。**

#### 🔴 四台 T0 主机不能被并进去

写在这里，因为它是唯一一个**真的会做错**的迁移，而理由不是成本。

**T0 机队是四台 `t4g.small`，分布在 `us-east-1`、`eu-west-1`、`ap-southeast-1`、`ap-northeast-1`
—— 三个大洲 —— 而那个地理分布本身就是实验。** Phase B-WAN 的证据包建立在**实测 68–223 ms 的 RTT 基
线**上，以及"分布式最终性在真实洲际延迟下形成，且没有任何节点持有法定人数"这一性质上。**EKS 集群是区域
性的。** 把这四台并进一个集群，会把 RTT 压缩到区域内个位数毫秒，**摧毁那次 48 小时 soak 要建立的性
质** —— 而网看上去仍然健康，**又是这个项目那个反复出现的形状**。

它们还是活的：网现在正在最终化，而 `qumbra-deploy` 的 **R3 适用 —— *"改实例类型、加主机……每一次都要
问，永远不要从之前的一个 yes 推断出批准。"*** 整合它们是一次销毁重建。

**那个 profile 里其他东西都是合理的候选。这四台不是** —— 而且如果它们被算进了促成这个想法的那个数字
里，那个算术需要去掉它们重算。

### 那个没人拉过的规格杠杆，对 A、C、F、G 一律适用

评估 G 的时候发现的，而它比"选哪一个"更值钱。

**`--test-threads=1` 意味着核数帮不上忙** —— workflow 自己的文件头就记着：*"一个 arm64 核在单线程工作
上比 M3 Max 慢约 1.8 倍，而 `--test-threads=1` 意味着核数帮不上忙。34 分钟是这台 runner 的地板；没有
缓存优化可找。"*

所以套件的实测画像是：

| | 实测 | 来源 |
|---|---|---|
| 峰值 RSS | **16.33 GB** | `PR #202` 和 `#195` 那两次运行的 `/usr/bin/time -v` |
| 墙钟 | **34–38 分钟** | 同上 |
| 有效并行度 | **1** | `-- --test-threads=1`，按 `CLAUDE.md` §5 不可商量 |

🔴 **当前 runner 是 8 核。套件只能用一个。** 另外七个每次运行都被付费闲置 35 分钟。真正的约束是
**内存 —— 要约 32 GB 才能装下 16.33 GB 的峰值并留余量** —— 以及单线程速度。**不是核数。**

**所以任何 self-hosted 方案要算价的都是"几个快核 + 32 GB"，不是 8 核。** 一个 `4 vCPU / 32 GB` 的
Graviton 类型跑这个套件的墙钟和 `8 vCPU / 32 GB` 一样，而便宜得多。**这个杠杆从来没被拉过，而且它和
runner 放在哪里无关** —— 它是这个工作负载的性质，由测量确立，也正是"按每分钟单价比较托管方案"是错误的
第一个问题的原因。

*（选项 A 上拉不动这个杠杆：GitHub larger runner 的目录按核数分档，所以在那里，付 8 个核的钱是拿到
32 GB 的代价。）*

### D. 只用 rig —— 删掉 CI

省下全部，放弃 R1。协调者会重新成为每一个验收数字的**唯一生产者兼唯一裁判**。**考虑到这个项目本月最糟的
几次事故都是协调者的判断错误、不是测试失败** —— 用一个"测试能满足而部署不能满足"的标准接受了 `PR #178`；
同一天合了 `#178` 和 `#182` 却没有把它们组合起来验 —— **移除唯一那个对协调者的结构性制衡，在几乎任何
价位上都是错的交易。**

### E. 把仓库改成公开

公开仓库的 Actions 分钟数免费。**`CLAUDE.md` 写着这个仓库是私有的、并且要保持私有**，所以这不是一个 CI
决定 —— 它是一个项目披露决定，只是恰好有 CI 后果，而且完全属于 Larry。

## 8. 建议

**先做 B，和预算问题脱钩。** 它免费、可逆、不需要授权，而且移除的是那一半买不到东西的花费。之后无论对
托管方式做什么决定，都是对着一个减半后的基线做的 —— 那才是值得拿来做决定的诚实数字。

**然后有意识地在 A 和 F 之间选** —— 不是 A 和 C —— **并且把 F 的运维成本算出来而不是假设掉。** 做完 B 之后，当前程序的成本
大约是每个**已合并** PR 一次套件 —— 是这个项目实际合并的速率，不是 builder 推送的速率。那个数字很可能
在 A 上就负担得起，从而使 C 的维护负担不成立。**这个算术在 B 之前做不了，因为今天的数字被没人读的运行
主导着。**

**不建议 D**，理由见 §7。**G 现在是有条件的，不是被否决** —— **如果 CI 必须为它justify**，它的控制面
费用是整个预算的约 3.5 倍；而**如果集群本来就存在，它完全不该算在 CI 头上**，这是 Larry 在 2026-08-02
提出的一个现实可能（§7G）。在那个前提下 **G 靠一次性 runner 反超 F**。**四台 T0 主机被排除在任何这类
整合之外 —— 见 §7G，理由是正确性，不是成本。** **本文不评估 E**，因为它不是一个 CI 问题。

**而在给任何方案算价之前，先拉那个规格杠杆。** §7G 结尾那一小节用测量确立了：套件用**一个核**、需要
**32 GB**，所以当前 runner 八个核里有七个每次运行都在付费闲置。**要算价的是 `4 vCPU / 32 GB`，不是
8 核** —— 这在"选哪一个"之前就已经改变了 C、F、G 的算术。

**另外，而且比上面所有事都大：去读 AWS 账单。** §7F 确认了四台 on-demand 实例在四个区域连续运行了 161
小时，没有 Savings Plan，没有 spot，而且**从来没有人看过它们花了多少钱**。那个数字很可能是本文档所讨论
的 $20 的好几倍。**无论 CI 怎么定，T0 机队都是更大的那一项，而且它是未测量的** —— 而 Savings Plan 如果
要买，应该按**那个**规模买，让 CI 搭车，而不是由 CI 来论证它。

## 9. 未决

| | 归属 |
|---|---|
| ~~`$20` 预算：提高、维持、还是维持并削减用量~~ | **2026-08-03 已重塑 —— 见 §10。** 产品级硬停错在形状而不只是数额：它把免费的 pre-filter 和付费 suite 的上限拴在了一起。已拆成对真正花钱的那个 runner 的 SKU 级硬停。未决的另一半是用一周 label 门控数据重校 $50 —— **Larry（R3）** |
| 要不要离开 GitHub 托管 | **Larry**，参考 §7F（§7C 和 §7G 是较弱的那些） |
| **任何 self-hosted 实例按 `4 vCPU / 32 GB` 而不是 8 核来选** | 协调者，在主机定下来之后 —— 有实测，见 §7G |
| **`default` profile 里其他 EC2 负载要不要整合进 EKS** | **Larry** —— 这不是 CI 决定；CI 只是搭车（§7G） |
| 确认四台 T0 被排除在那次整合之外 | **Larry（R3）** —— §7G 写了为什么必须排除 |
| **要不要买 Savings Plan，以及按什么规模买** | **Larry（R3）** —— 见 §7F：适配它的是 T0 机队，不是 CI |
| **去读 T0 机队真实的 AWS 账单** | 未指派，而它是本文档里最大的一个未测量数字 |
| 仓库可见性 | **Larry** |
| ~~触发条件改动（§7B）~~ | **2026-08-02 已完成** —— `types: [labeled]` + `verify` 门。见 §7B。 |

## 10. stop-usage 的爆炸半径,与 SKU 拆分(2026-08-03)

**本节修的缺陷是一个形状,不是一个数字。** 原先的 `$20` 预算是挂在 `actions` 上的
`ProductPricing`,且 `prevent_further_usage: true` —— 触顶那天,**所有** Actions workflow 一起
停,包括跑在标准 runner 免费额度内、根本不花钱的 `prefilter.yml`。便宜的守卫和昂贵的 suite 一起
死。而且失败是安静的:workflow 只是不再启动,没有任何东西通知车队,第一个症状是四个 baton 又开始
排 rig —— **恰好是这套 CI 存在就为了消灭的状态**,被本该保护它的预算恢复了。

### 数字,方法同 §4

2026-08-03 取自 `gh api /organizations/qumbra-labs/settings/billing/usage`:

| | 值 | 来源 |
|---|---|---|
| 8 月截至 08-03 的花费 | **$20.00 中的 $14.14** | 账单页与 usage API 一致 |
| 花在哪 | **100% 一个 SKU:`Actions Linux ARM 8-core`** | 1,010 计费分钟 ≈ $0.014/分钟,三条用量记录($8.76 + $4.84 + $0.53) |
| 标准 `Actions Linux` 分钟 | 87 分钟,**$0** | 在套餐附带额度内 —— pre-filter 从未花过钱 |
| 剩余空间 | $5.86 ≈ **11 次 suite**(每次 $0.55) | 按 #210 之后的验收节奏,只够几天 |

⚠️ **最后一行原本写的是"≈ 8 次 suite(按 §4 的 ~$0.7)"。2026-08-04 修正,错了两层。** §4 的数字是
**$0.49**,不是 $0.7 —— §4 的存在本身就有一半是为了撤回 `PR #191` 记录的那个 $0.7,把它引回来等于
自引一个本文档已经收回的数。而且 $0.49 本身也不是该拿来用的那个:它是 **#210 之前那批样本**的均值,
里面混着被提前取消的 builder push 运行。正确的单次成本应该用本节自己的费率、对本节自己的样本推导
—— 见下面的重校。

所以产品级上限把两条毫无共性的流混为一谈:一个占花费 100% 的付费 SKU,和一个占常开守卫 100% 的
免费层。

### 拆分,2026-08-03 决定

| 预算 | 范围 | 数额 | stop usage | 职责 |
|---|---|---|---|---|
| **新建** | `SkuPricing`,`actions_linux_8_core_arm` | $50 | **是** | 硬停,只拦唯一真正花钱的东西 |
| **重塑** | `ProductPricing`,`actions` | $60 | **否 —— 仅提醒** | 对一切*不是*大 runner 的花费做预警:存储超额、标准分钟超出附带额度 |

$50 ≈ **每月 91 次 suite ≈ 每天 3 次验收**(2026-08-04 从"70 ≈ 每天 2–3 次"修正,与上面那行同因)。
**这是过渡性护栏,不是 §8 的托管决定** —— 一周 label 门控数据后重校;若 A vs F 落到 self-hosted,
则整体重推。

经 budgets API 执行(需要 `admin:org`):

```
POST  /organizations/qumbra-labs/settings/billing/budgets
      {"budget_type":"SkuPricing","budget_product_sku":"actions_linux_8_core_arm",
       "budget_scope":"organization","budget_amount":50,"prevent_further_usage":true, …}
PATCH /organizations/qumbra-labs/settings/billing/budgets/7adffff2-…
      {"budget_amount":60,"prevent_further_usage":false, …}
```

验证用同一个 API:`GET …/settings/billing/budgets` 必须显示如上两行。一个值得记录的可复用技巧:
**合法的 SKU 标识符没有任何地方可以列出,但用一个瞎编的 `budget_product_sku` 去 `POST`,错误消息
会返回完整的合法清单。**

### 重校(2026-08-04)—— 不完整,但它说明 $50 没有余量

§10 要求"一周 label 门控数据后重校"。现在只有 **2.3 天**,不是一周;之所以现在就记,是因为修正上面
那行算术必须先把单次成本推导对。当作一次中间读数看。

`suite-arm64.yml` 在门控落地(`c9b5055`,2026-08-02T01:14:50Z)之后到 2026-08-04T08:46Z 的**全部**记录:

```
21m 取消 · 39m · 39m · 39m · 40m · 39m · 38m · 39m · 0m skipped
```

| | 值 | 怎么来的 |
|---|---|---|
| 完成的验收 | **7 次** | 均值 39.0 分钟,区间 38–40 —— 分布极紧 |
| 单次验收成本 | **$0.55** | $0.014/分钟 × 39.0 分钟,两个数都来自本节 |
| 流逝时间 | 55.5 小时 | 门控落地 → 现在 |
| **节奏** | **每天 3.03 次验收** | 7 / 2.31 天 |
| 门控后花费 | $4.12 | 294 计量分钟 × $0.014 |
| **月度推算** | **约 $54** | 91 次验收 × $0.55,加约 13 次取消运行 × $0.29 |

🔴 **$50 大约正好是观测节奏下的一个月,没有余量 —— 它会在月末附近触发,而不是当一个谁也够不着的
天花板。**这不是提额的理由:一个偶尔触发的上限正在履行职责,而且 SKU 拆分之后触发它不再会把
pre-filter 一起带走。这是"要预期到它会发生,并在那之前把 §8 定下来"的理由。

那条 `0m skipped` 是标签门在正确工作 —— 一个非 `verify` 标签触发了 workflow,job 的 `if:` 拒绝了它,
零成本。

**方法学备注,因为这是最容易被重复犯的错。**同一批数据的一次更早读数得出 **每天 6.9 次**,做法是拿
运行次数除以**第一次到最后一次之间的跨度**。这会静默地把空闲时间排除在外 —— 这里是一段 24 小时、
一次验收都没有的空档 —— 从而把节奏虚高 2 倍以上。要除以**门控落地以来的流逝墙钟时间**,不是除以
运行恰好占据的那个窗口。

⚠️ **08-03 那张表里有一个数字已经过期。**标准 `Actions Linux` 分钟当时是 `87 分钟,$0`,在套餐附带
额度内。到 2026-08-04 已是 **171 分钟,$1.03** —— 附带额度已经耗尽,所以*"pre-filter 从未花过钱"*
现在是一句关于过去的话。这不削弱拆分,反而加强它:$60 的仅提醒产品预算现在盯着的是一条真的会花钱
的流,而不是一条不可能花钱的流。

### 实测更新(2026-08-07)—— 节奏塌了,且 08-04 的一个数字复现不出来

用的是 §10 用过的同两个 API(`/organizations/qumbra-labs/settings/billing/{usage,budgets}`),
所以下面每一行都能和上面的表逐行对照。

**1. 拆分仍然在位。** `GET …/settings/billing/budgets` 返回的正是 §10 那张表:
`SkuPricing` on `actions_linux_8_core_arm` 为 **$50、`prevent_further_usage: true`**,
`ProductPricing` on `actions` 为 **$60、`prevent_further_usage: false`**,两条都告警给 `lai3d`。
§10 写着 *"Verification is the same API"*——这就是那次验证,四天之后。

**2. 支出,而且仍然只有一个 SKU。**

| sku | 用量 | gross | discount | **net** |
|---|---|---|---|---|
| `Actions Linux ARM 8-core` | 1,049 分钟 | $14.69 | $0.00 | **$14.69** |
| `Actions Linux`(标准) | 250 分钟 | $1.50 | $1.50 | **$0.00** |
| `Actions storage` | 0 | $0.00 | — | **$0.00** |

净支出 100% 归属 `qumbra-lab`。推得费率 $14.69 / 1,049 = **$0.014/分钟**,与 §10 一致。

**3. 🔴 ~$54 的预测没有兑现,因为节奏塌了。** §10 的重校测得 **3.03 次验收/天**,据此预测当月约 $54。
自那次读数以来:

| | 2026-08-03(§10) | 2026-08-07 | 差 |
|---|---|---|---|
| ARM 8-core 分钟 | 1,010 | 1,049 | **+39 ≈ 一次验收** |
| 净支出 | $14.14 | $14.69 | **+$0.55** |

**四天一次验收 ≈ 0.25 次/天,比预测低一个数量级。** 按这四天的速率,$50 本月根本达不到,
§10 那句 *"it will trip near month end"* 目前是假的。可能的原因,**只是提出、不断言**:本周
lab 的工作是单 crate 的 baton(#281、#284),它们的任务书明确写了只跑 targeted 测试、
**不占 rig 也不占验收槽**。若果真如此,下一个碰共识面的 baton 一到,节奏和预测都会回来——
**不要把安静的四天读成新基线。**

**4. ⚠️ 08-04 那条"包含额度已用尽"的修订复现不出来。** 它记的是标准 runner *"171 min, $1.03"*,
并据此断定 *"包含额度已用尽,所以'pre-filter 从未花钱'现在是一句关于过去的话"*。今日实测:
**250 分钟、gross $1.50、discount $1.50、net $0.00**,而计费总览独立显示
**243 / 3,000 包含分钟已用——8%**。两个面都说额度远未用尽。

最可能的解释(说"最可能"而不是"确定",因为 08-04 的原始响应已不可回溯):**把 gross 读成了 net。**
usage API 分别报告 `grossAmount`、`discountAmount` 和 `netAmount`,而**只有 `netAmount` 计费**
——$1.03 具有"折扣未被减去的毛额"的形状。

**后果比算术重要。** §10 论证拆分被强化,理由是 $60 的产品级预算"如今监视的是一条真的会花钱的流,
而不是一条不可能花钱的流"。按今日数据,那条流仍然**一分不花**——所以 $60 仍是一个针对尚未开始之事的
早期预警,而那正是 §10 设计它时的定位。**拆分本身没有被削弱,被削弱的是它一句论证。**

**5. org 里多了一个仓库,它不花钱。** `qumbra-labs/qumbra-explorer-web`(2026-08-06 创建)有两个
workflow,都跑 `ubuntu-latest`:`test.yml`(亚秒级)和 `image.yml`(纯 COPY 的多架构构建,
**不需要 QEMU 也不需要 arm64 runner**——Dockerfile 里没有任何 `RUN`,所以目标平台上没有东西要执行)。
它在用量数据里**根本没有出现**,而它的 SKU 正是净额为 $0 的那一个。之所以记下来:一个新开 CI 的仓库
是计费数字最显眼的甩锅对象,而这里 usage API 把净支出 100% 归给了 `qumbra-lab`。

**6. 怎么读这份文档——它现在在四个小节里有四个支出数字。** $9.31(§4,08-02)、$14.14(§10,08-03)、
上面那个 $1.03(08-04,已被第 4 条撤回)、$14.69(本节)。**要和最新的比,不要和第一个搜到的比。**
本次更新之所以存在,一部分正是因为写它的路上犯了这个错:拿一张新的计费截图去比 §4 的 $9.31,
看起来像陡增,而 §10 早就记着 $14.14,真实的四天增量是 $0.55。

### 一条本次不动的边界

`packages` 保持 $0 + stop usage **开**。GHCR 上的 node 镜像是公开的,公开包存储免费,今天没有任何
在跑的东西受影响 —— 但哪天有人推**私有**镜像,push 会栽在这条预算上,而报错读起来像权限问题。
记在这里,好让那一小时花在这句话上,而不是花在 GHCR 鉴权文档上。

---

*2026-08-02 由协调者会话写下，起因是 Larry 的账单截图让花费第一次变得可见。§4 的测量可用 `gh run list`
和组织账单页复现；$9.31 是其中唯一一个"取来的"而非"推导出来的"数字。§10 由评审者会话(Larry 指派)
于 2026-08-03 在第二张账单截图之后补写;其数字取自 usage API 与 budgets API,均就地引用。*

---

## RETIRED 2026-08-21 — `suite-arm64.yml`, and what it cost to keep

**Larry's order.** The workflow is deleted; the acceptance bar is now
`acceptance-graviton.yml` (`verify-graviton`), and `CLAUDE.md` §5 has been repointed.

**It finished the job it was built for.** Its own header said *"COLLECTING COMPARISON DATA.
Still not the acceptance bar"* — it existed to compare the GitHub-hosted `qumbra-arm64-8`
against the self-hosted Graviton lane, running a byte-identical
`cargo test --release --workspace --locked`. The verdict is recorded above:
**seven same-tree comparisons, seven agreements, zero disagreements.**

**Why retiring beat moving it.** The obvious cost fix was to repoint its `runs-on` at
`[self-hosted, graviton-rig]`. That would have made it compare Graviton against Graviton —
paying the bill while deleting the reason. **A workflow whose purpose is comparison cannot be
moved onto the thing it compares against.**

**What it was costing.** Measured 2026-08-21 from the org budget page and the run history:

| | |
|---|---|
| Actions total | **$62.26** of a $100 budget |
| of which `Actions Linux ARM 8-core` | **$47.57** of an $80 SKU budget, `Stop usage: Yes` |
| ARM SKU runs since 08-01 | **413** → ~$0.115/run |
| `suite (arm64)` share | **152 runs**, the largest single consumer |

🔴 And that SKU budget has a second edge: the workflow headers note that exhausting it
**stops the other paid lanes with it** — an expensive month could take a release cut or an
image build down as collateral.

**Every paid runner in the org, for whoever asks next.** Only two repos spend at all:

* `qumbra-lab` — `explorer-image` / `node-image` / `kit-fixture-mint` on the ARM SKU;
  `release-binaries` (macOS 10x, Windows 2x); `windows-x86_64` (2x); `prefilter` (1x, 563
  runs but the cheapest lane and the one that stops the expensive ones).
* `qumbra-explorer-web` — two `ubuntu-latest` workflows, 17 runs. Negligible.

Everything else is free: all four wallet workflows run on a self-hosted Mac, and
`acceptance-graviton`'s suite job runs on the Graviton rigs.

**Still on the ARM SKU after this retirement:** `explorer-image` (159 runs) and `node-image`
(96). Both are Docker builds and **Docker is not installed on the Graviton rigs** — moving
them needs `docker` + `buildx` in the module's `user_data` first, which is a `user_data`
change and therefore carries the STOP/START hazard documented in
`qumbra-deploy/terraform/ci-runner/README.md`.
