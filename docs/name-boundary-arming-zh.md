# 名字服务边界 —— 启用（arming）程序（lab #367）

> [English](name-boundary-arming.md)

**状态：提前备好 —— T2 门开之前不可执行**（[#370] 的 T1 上线清单清空；门的排放
那一半已于 2026-08-12 通过）。趁边界日的机制记忆还新鲜、照
`i299-emission-boundary-activation.md` 的模子写下，使启用日是一张清单而不是一场
考古。本程序激活的施工已作为 PR #381 惰性合并；[#367] 是本文档所属的追踪器。

[#370]: https://github.com/qumbra-labs/qumbra-lab/issues/370
[#367]: https://github.com/qumbra-labs/qumbra-lab/issues/367
[#375]: https://github.com/qumbra-labs/qumbra-lab/issues/375
[snapshot-transplant]: https://github.com/qumbra-labs/qumbra-lab/issues/359#issuecomment-5300960029

> **复核 —— 2026-08-16（对 `main` @ 6703630）。** 本 runbook 引用的每处代码/机制在
> main 上仍成立:`commitment_at_with_no_boundary_is_v2_everywhere` 与
> `validate_body_rider_leg_end_to_end` 测试、`validate_body_above` /
> `commitment_above` 钻孔 seam、`NAME_RULE_BOUNDARY_HEIGHT = None`(仍惰性)、以及
> §5 边界-tie 的 telemetry 字段(`schain=` / `stipid=` 都在)。**程序无需改动。** 但前置
> 状态动了 —— 下面的清单是计划,这里是每条今天的实况:
>
> | # | 前置 | 2026-08-16 状态 |
> |---|---|---|
> | 1 | T2 门开(T1 上线 #370 清空) | 🔴 未过 |
> | 2 | mempool rider leg | ✅ #385/#390 |
> | 3 | #375 边界-tie 输方已修 | ✅ **CLOSED — PR #416**(convergence lock + 恢复文档;§5 step 2 已 grounded) |
> | 4 | #369 演练覆盖 body-format 边界 | 🟡 在飞(`claude/i369-halt-drill`) |
> | 5 | 0x06 telemetry 全舰队 | ✅ **live 已验** —— `explorer/v1/health.json` 的 `supply.epochs[].burned` 存在(=0),非 null |
> | 6 | #387 同名 reveal 竞争已闭 | ✅ **CLOSED — PR #390** |
> | 7 | Larry 盖边界高度 | ⬜ 你定,卡在 1 |
> | 8 | 费用表复批 | ⬜ 盖章时 |
>
> 两条硬共识门(3、6)已闭,4 在飞。剩下的是普通 T2 门:T1 上线(1)+ 你盖章(7/8)。
>
> **一处确认仍欠(未变):** §2 step0 的 `qumbra-node halt-status` name-boundary 横幅
> 在 main 上仍不存在(本次 grep 复核确认)。它欠在 arming 日镜像构建**之前**,正如
> §2 已标。

## 0. 两句话说清改的是什么

在 `NAME_RULE_BOUNDARY_HEIGHT` 之上：交易可以携带**名字 rider**（commit /
reveal / renew），区块 body 换 **v3 编码**承诺（第一次经由 halt 边界而非重铸抵达
的 body 格式变更），注册交易申报费里的名字费那一半被**销毁**——从 coinbase note
里减去，报在供应 attestation 的 `burned` 列。边界之下——直到启用日的整条链——
什么都不变，这个性质由 `commitment_at_with_no_boundary_is_v2_everywhere` 锁住。

## 1. 前置条件（八条全要，按序 —— 没有一条是走过场）

1. **T2 门已开**：[#370] 清单清空、T1 公开挖矿已运行足够久，FCFS 注册才算公平——
   公平性论证（公开前的注册全是内部人注册）记录在 [#367] 的提前激活讨论里，
   这是 Larry 的裁决，不是 ops 判断。
2. **mempool 的 rider leg 已落地**（本 PR）：`Mempool::admit` 跑与
   `validate_body` 相同的 rider 规则,所以不会收下一笔区块验证会拒的注册——
   rider 引入的 #278 引爆器（commit 的费用等于 `posted_fee`,裸费用检查放行、
   而验证拒绝）已关闭并变异锁定。没有这条,启用前钱包点一次 Post-Commit 就能
   毒化 mempool。
3. **[#375] 已修并合并其测试**——冻结边界 tie 的输方 finalize 自己没有的块，
   是边界日现场发现的，不能带着它赴下一次边界。
4. **[#369] 常备演练已建成且覆盖 body 格式边界**——8,640 那次 halt 改的是验证
   规则，这次改的是 wire。演练必须在套件内把委员会跑过一次 v2→v3 的 halt
   （`validate_body_above` / `commitment_above` 钻孔 seam 正为此而在）。
5. **`0x06` telemetry wire 已全舰队部署**（本 PR 的 bump：`burned` 尾段 +
   explorer 列）。随任意一次常规镜像滚动即可——它是惰性数据管道；
   `READABLE_TELEMETRY_VERSIONS` 保证滚动期间 opview 不失明。验证：
   `curl explorer/v1/health.json | jq '.supply.epochs[0].burned'` 答 `0` 而非
   `null`。
6. **同名 reveal 竞态已关闭
   （[#387](https://github.com/qumbra-labs/qumbra-lab/issues/387)）**——admit
   那条腿（前置条件 2）核对 rider 时用的是空 pending 集，于是同一个名字的两笔
   reveal 都能入池；`Mempool::assemble` 不认名字，会把两笔装进同一个模板，而
   `validate_body` 的同块 tie 规则会拒掉这个块——节点给自己装配无效块。驱逐
   同样不认名字（只看 nullifier/anchor），一笔被别人抢先挖出的 reveal 会滞留
   池中，正是前置条件 2 在 admit 处关掉的那种挖不出去的毒交易。边界之下不可达；
   而启用日就是抢注高峰，同名撞车最可能的时刻——所以必须在盖章之前关掉，
   不能等它自己现身。
7. **Larry 在 [#367] 上盖边界高度**——留足提前量的 halt 高度（8,640 重盖那次
   只留了约 4.5 小时跑道，靠现场修三个缺陷才够用；这次给 ≥2 天），落在 epoch
   边界上更顺但并非必须。
8. **盖章时复批费用表**——常量于 2026-08-12 合并（按长度 1/32/128/512/2048
   QMB、365+90 epoch、8/2,304 窗口）。若 QMB 的购买力现实已变，此刻是重述或
   重盖的时机；启用之后它们只能在更晚的边界移动。

## 2. 第 0 步 —— 盖常量、翻 golden

在 current `main` 的 worktree 上：

- `NAME_RULE_BOUNDARY_HEIGHT: Option<u64> = None` → `Some(<盖章高度>)`
  （`crates/qlab-devnet/src/names.rs`）。
- 惰性合并的锁定测试**此刻必须失败并在同一提交内退役**，换上武装态的对偶
  （各自在注释里点名接替者）：`commitment_at_with_no_boundary_is_v2_everywhere`
  → 边界分割 golden；`validate_body_rider_leg_end_to_end` 的出厂规则
  `CommitmentMismatch` 分支 → 武装态正路。
- 在盖章边界处重推 v3 body 承诺 golden（`Some(8_640)` 的钻孔 golden 留作格式
  锁；出厂规则 golden 正当地移动一次并锁定）。
- `qumbra-node halt-status` 必须像横幅排放边界那样横幅名字边界——若没有，
  这个 seam 欠在镜像构建**之前**。

第 0 步的验收 = `suite-arm64` 上的全量套件（重负载不落笔记本——2026-08-12 起
的常规），算术逐项对账。

## 3. 滚动之前把两个镜像都建好

i299 模式照抄（`deploy/docker`；若用特性开关则走 `NODE_FEATURES` build-arg
模式，否则两个提交出两个 tag）：

- **armed** —— 在盖章高度 halt，横幅写明；
- **resume** —— 边界之后具备 v3 能力，横幅写明。
- **先推 resume**（i299 规矩：紧急时刻需要的镜像必须已经在 GHCR 上）。

## 4. 滚 armed 镜像 —— 六台全滚

node0–3 **加 svc0/svc1**（8,640 的教训：svc 主机晚于边界要付代价——explorer
观察节点在 `halted 8640` 上卡了一天就是这个遗漏）。一次一台，逐台核验
`slag=0` 归队，全程盯 R2 守卫（同高 fid 分裂）——OPERATOR §3/§7 管辖。

## 5. Halt、边界 fid、resume

i299 §5–6 照抄，另加这次已预先合并的两个边界日修复（#360 停机提案维持、
#362 REPUSH 节拍）：

1. 网在盖章高度 halt；每台主机横幅确认。
2. **协调者裁定边界 fid：至少 3/4、单一身份**——此处分裂即 R2，全停，保全
   现场。
   **边界 tie 输方（boundary-tie loser）**是另一种可恢复形态：主机停在 H，
   finalized checkpoint 指向 A，已应用 tip 却是 H 上的同胞块 B，并打印
   `FINALIZE refused head=state ... why=not-held`。让主机保持 halt 且保持连接：
   主路径会经有界 near-tip body 窗口重索 A，只 rewind 一次，再走正常 state
   funnel 应用 A。用 `stip=H`、`dfin=H`、一致的 `stipid`/`dfinbh`、
   `schain=main`、`breq=0` 确认恢复；少数派密钥账本的 `sid` 按设计仍是 B，
   它是 never-double-sign 的取证记录。若没有可达 peer 能提供 A，则走
   [snapshot-transplant] 程序——只复制 donor 的 `snapshot.bin` + `blocks.log`，
   保留本机自己的 finalizer 账本、halt marker 与配置。代码路径是主路径；
   transplant 是服务不可用或 pre-#375 binary 的后备路径。
3. 按 §6 分波 resume（runbook 说可并行处并行），svc 主机在同一波次集合里。
4. 链恢复；第一个边界后检查点在 v3 body 下 finalize。

## 6. 验证规则真的咬合了（§7 纪律）

- `qumbra-node audit-names --data-dir <dir> --from <边界+1>` → **exit 0、
  registry AGREES**——独立跑 ≥3 台。
- `audit-emission --from <边界+1>` → exit 0（销毁不得弯曲排放规则：coinbase
  仍精确、费用拆分正确）。
- 经公共边缘 `GET /v1/names?from=<边界>&to=<tip>` → 200、可解码、该有 rider
  处有 rider。
- `GET /v1/names?name=probe` → **400 且带 D2 拒绝文案**（路由层的墙穿过真实
  边缘仍然立着）。
- Explorer `health.json` 的 `burned` 列反映最初的真实注册（第一笔 reveal
  上链后非零）。
- **第一笔端到端注册**：操作者钱包跑 `names register <name>` → commit → 窗口
  → reveal → `names sync` 看见 → `send --to <name>.qmb` 在 FirstUse 处拒付 →
  `names pin` → 发送成功。这是演练链条的实况对应，也是 [#367] 的最后一格。

## 7. 回滚姿态

Halt 之前：回滚 = 滚回启用前镜像（边界在未来；什么都没变过）。边界 finalize
之后：**没有回滚**——v3 区块已存在；pre-#367 的二进制会拒绝携带 rider 的日志
记录（追加变体设计使然），也拒绝边界之上的整条链。决断点是 §5 第 2 步的 fid
裁定，与排放日相同。

## 启用时才做、现在只是别弄丢（停车场）

- opview 的 `burned` 列（按 `0x06` 载荷版本门控——从本次 arming 准备 PR 里
  推迟，因为 opview 读的是远端各代 vintages，且它的供应表以一致性而非明细
  为业）。
- T2 时钟启动时 `name-service-survey-2026-08.md` 落盘 design 侧（完整溯源
  pass；报告在那之前住在 design #139 上）。
- Brief 里留给边界的数字：宽限期解析行为已按 brief 的倾向**实现为"仍解析、
  带标记"**，随 PR #381 获批；边界事务只剩费用数额的修订。
