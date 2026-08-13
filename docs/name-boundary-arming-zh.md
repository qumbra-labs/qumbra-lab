# 名字服务边界 —— 启用（arming）程序（lab #367）

> [English](name-boundary-arming.md)

**状态：提前备好 —— T2 门开之前不可执行**（[#370] 的 T1 上线清单清空；门的排放
那一半已于 2026-08-12 通过）。趁边界日的机制记忆还新鲜、照
`i299-emission-boundary-activation.md` 的模子写下，使启用日是一张清单而不是一场
考古。本程序激活的施工已作为 PR #381 惰性合并；[#367] 是本文档所属的追踪器。

[#370]: https://github.com/qumbra-labs/qumbra-lab/issues/370
[#367]: https://github.com/qumbra-labs/qumbra-lab/issues/367

## 0. 两句话说清改的是什么

在 `NAME_RULE_BOUNDARY_HEIGHT` 之上：交易可以携带**名字 rider**（commit /
reveal / renew），区块 body 换 **v3 编码**承诺（第一次经由 halt 边界而非重铸抵达
的 body 格式变更），注册交易申报费里的名字费那一半被**销毁**——从 coinbase note
里减去，报在供应 attestation 的 `burned` 列。边界之下——直到启用日的整条链——
什么都不变，这个性质由 `commitment_at_with_no_boundary_is_v2_everywhere` 锁住。

## 1. 前置条件（六条全要，按序 —— 没有一条是走过场）

1. **T2 门已开**：[#370] 清单清空、T1 公开挖矿已运行足够久，FCFS 注册才算公平——
   公平性论证（公开前的注册全是内部人注册）记录在 [#367] 的提前激活讨论里，
   这是 Larry 的裁决，不是 ops 判断。
2. **[#375] 已修并合并其测试**——冻结边界 tie 的输方 finalize 自己没有的块，
   是边界日现场发现的，不能带着它赴下一次边界。
3. **[#369] 常备演练已建成且覆盖 body 格式边界**——8,640 那次 halt 改的是验证
   规则，这次改的是 wire。演练必须在套件内把委员会跑过一次 v2→v3 的 halt
   （`validate_body_above` / `commitment_above` 钻孔 seam 正为此而在）。
4. **`0x06` telemetry wire 已全舰队部署**（本 PR 的 bump：`burned` 尾段 +
   explorer 列）。随任意一次常规镜像滚动即可——它是惰性数据管道；
   `READABLE_TELEMETRY_VERSIONS` 保证滚动期间 opview 不失明。验证：
   `curl explorer/v1/health.json | jq '.supply.epochs[0].burned'` 答 `0` 而非
   `null`。
5. **Larry 在 [#367] 上盖边界高度**——留足提前量的 halt 高度（8,640 重盖那次
   只留了约 4.5 小时跑道，靠现场修三个缺陷才够用；这次给 ≥2 天），落在 epoch
   边界上更顺但并非必须。
6. **盖章时复批费用表**——常量于 2026-08-12 合并（按长度 1/32/128/512/2048
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
