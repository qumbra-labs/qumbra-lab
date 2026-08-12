# 发行规则边界(高度 8,640,约 2026-08-12)—— 一页索引

> [English](emission-boundary-index.md)
> ✅ **边界已穿越 —— 2026-08-12。**08:20:55 +08 停机（四台同 tip）,**11:55:42 敲定**
> （fid `7925d1de`,四票全）,12:16:51 链在精确调度下复活,§7 `audit-emission --from 8641`
> 全舰 exit-0。issue #299 与 #303 已关闭。停机窗口内现场发现并修复三个缺陷——#360
> （边界签名被挖矿门锁死）、#362（投票中继孤岛）、以及冻结的 tip 平局（败方收敛缺口
> 立案为 #375）——完整叙事见
> [`qumbra-deploy tasks/boundary-day-8640-2026-08-12.md`](https://github.com/qumbra-labs/qumbra-deploy/blob/main/tasks/boundary-day-8640-2026-08-12.md)
> 与 #299 线程。**本页自此为历史档案**;下方的 go/no-go 程序按原样执行完毕
> （执行中依 STOP 通告现场修正）,并保留为未来任何停机边界的模板。


> 🔴 **2026-08-11 重新盖章:边界从 18,000 改为 8,640。** 见
> [Larry 在 issue #299 的裁决](https://github.com/qumbra-labs/qumbra-lab/issues/299#issuecomment-5248469483)
> 和 [`i299-emission-boundary-activation-zh.md`](i299-emission-boundary-activation-zh.md)
> 开头的重盖章说明。以下全部按 **8,640** 改写;"当前状态"一节记录的是先前在 18,000
> 武装的舰队,已被取代,须重建并重新滚动。

**边界日从这里开始读。**本页只有指针 + go/no-go 决策;细节全在下面四份文档里。

## 两句话说清它是什么

在**高度 8,640**,规范发行调度从平台相关的 `f64` 形式切换到整数精确形式,共识开始强制
`body.coinbase == coinbase_exact(height)`——于是区块发行变得不可伪造、跨平台逐位一致。
它是**高度不是日期**(按 ~48 块/小时约 2026-08-12——盯 tip,永远别盯日历)。

## 为什么是停机升级,不是热切

共识规则变更必须在**每个节点的同一高度**生效,否则分叉(一个节点用旧规则判块、另一个用
新规则)。所以 armed 二进制**让全网在 8,640 停机**,resume 二进制带它过界。这是 halt-height
升级机制(M11,#74/#81)第一次服务于**真实的**规则变更。

## 四份文档

| 你想要… | 读 |
|---|---|
| **是什么/为什么**(规则、疤痕保留、T1 门) | `qumbra-design/protocol-spec.md` §6 修正块(EN+ZH) |
| **怎么做**(边界日我逐步执行的) | [`i299-emission-boundary-activation-zh.md`](i299-emission-boundary-activation-zh.md) §0–8(EN+ZH) |
| **记录**(−4114 缺陷、普查、裁决) | lab issue [#299](https://github.com/qumbra-labs/qumbra-lab/issues/299) + [#303](https://github.com/qumbra-labs/qumbra-lab/issues/303) |
| **live 状态**(舰队 digest、resume 镜像、6 台注记) | `qumbra-deploy/OPERATOR.md` §3 |

## 序列,以及唯一一个不由我强行决定的判断

1. 净爬到 8,640 → 四台 armed 主机**停机**(finality 冻结在 8,640)。
2. 🔴 **GO/NO-GO —— R2 门。**四台必须都读 `final=8640` 且**同 `fid`**。这里 fid 分裂(两台
   在 8,640 敲定了不同东西)是 **R2 停点**:不许滚 resume,保留状态,升级给 Larry。其余皆继续。
3. 把 **resume** 镜像滚到**全部 6 台**——四台舰队节点**加** svc0/svc1(svc 观察节点早于发行门,
   OPERATOR §3 / deploy PR #115)。
4. ≥⅔ 委员会切到 resume 后,净在 8,640 之上按精确调度恢复出块。
5. 验证:`qumbra-node audit-emission --from 8641` 四台 exit 0;opview/explorer 读 epoch 7
   (跨界)`AGREED`、epoch 1 `KNOWN-SCAR −4114`(不升级告警)。

## 当前状态(2026-08-11,重盖章)

- **已取代:先前在 18,000 武装的舰队。** 截至 2026-08-10,四台舰队全在
  `emission-armed-b2fce07`(`06baa298…4338`),halt plan `halts at height 18000`,v1.0,resume
  镜像已构建+推送(`emission-resume-b2fce07``08b6c306…8385`,pin 见 PR #336)。按重盖章裁决,
  那次武装已过期:两个镜像都必须在 **8,640** 重建(新 pin 从改动后的树重新推导,见本次 R3
  PR),四台主机重新滚动——第三次生产滚动,裁决接受了它自己的 #300/#287 级风险。
- **边界处待办**:在 8,640 重建两个镜像 → 滚 armed 到四台 → 停机 → R2 fid 检查 → 6 台
  resume 滚动 → 验证。盯 tip 逼近 **8,640**。
- **中止线,为 R3 重述**:舰队绝不能以混合状态撞上边界。若四台主机没有在高度 **~8,300**
  之前(按重盖章节奏约 7 小时前置期)都读到 `ARMED — halts at 8640`,立刻处理混合状态——
  补完滚动或回退到 18,000-armed 镜像——把边界问题带回 #299 重新蓋章。

**若 tip 已进入 8,640 的余量之内而舰队未就绪**(resume 镜像缺失、pin 错),在 #299 上重盖边界章
而非抢高度——超一点只多几天未强制;差一点会让活网停在没有 resume 二进制的边界上。仅在镜像
构建前合法;新高度必须 `≡ 0 (mod 8)`。
