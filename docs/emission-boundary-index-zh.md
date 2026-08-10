# 发行规则边界(高度 18,000,约 2026-08-20)—— 一页索引

> [English](emission-boundary-index.md)

**边界日从这里开始读。**本页只有指针 + go/no-go 决策;细节全在下面四份文档里。

## 两句话说清它是什么

在**高度 18,000**,规范发行调度从平台相关的 `f64` 形式切换到整数精确形式,共识开始强制
`body.coinbase == coinbase_exact(height)`——于是区块发行变得不可伪造、跨平台逐位一致。
它是**高度不是日期**(按 ~48 块/小时约 2026-08-20——盯 tip,永远别盯日历)。

## 为什么是停机升级,不是热切

共识规则变更必须在**每个节点的同一高度**生效,否则分叉(一个节点用旧规则判块、另一个用
新规则)。所以 armed 二进制**让全网在 18,000 停机**,resume 二进制带它过界。这是 halt-height
升级机制(M11,#74/#81)第一次服务于**真实的**规则变更。

## 四份文档

| 你想要… | 读 |
|---|---|
| **是什么/为什么**(规则、疤痕保留、T1 门) | `qumbra-design/protocol-spec.md` §6 修正块(EN+ZH) |
| **怎么做**(边界日我逐步执行的) | [`i299-emission-boundary-activation.md`](i299-emission-boundary-activation-zh.md) §0–8(EN+ZH) |
| **记录**(−4114 缺陷、普查、裁决) | lab issue [#299](https://github.com/qumbra-labs/qumbra-lab/issues/299) + [#303](https://github.com/qumbra-labs/qumbra-lab/issues/303) |
| **live 状态**(舰队 digest、resume 镜像、6 台注记) | `qumbra-deploy/OPERATOR.md` §3 |

## 序列,以及唯一一个不由我强行决定的判断

1. 净爬到 18,000 → 四台 armed 主机**停机**(finality 冻结在 18,000)。
2. 🔴 **GO/NO-GO —— R2 门。**四台必须都读 `final=18000` 且**同 `fid`**。这里 fid 分裂(两台
   在 18,000 敲定了不同东西)是 **R2 停点**:不许滚 resume,保留状态,升级给 Larry。其余皆继续。
3. 把 **resume** 镜像滚到**全部 6 台**——四台舰队节点**加** svc0/svc1(svc 观察节点早于发行门,
   OPERATOR §3 / deploy PR #115)。
4. ≥⅔ 委员会切到 resume 后,净在 18,000 之上按精确调度恢复出块。
5. 验证:`qumbra-node audit-emission --from 18001` 四台 exit 0;opview/explorer 读 epoch 15
   (跨界)`AGREED`、epoch 1 `KNOWN-SCAR −4114`(不升级告警)。

## 当前状态(2026-08-10)

- **已武装。**四台舰队全在 `emission-armed-b2fce07`(`06baa298…4338`),halt plan
  `halts at height 18000`,v1.0。滚动后核实健康(fid 一致、finality 推进)。
- **resume 镜像已构建+推送**:`emission-resume-b2fce07`(`08b6c306…8385`),v1.1-exact-emission。
  pin 已设(PR #336,协调者独立复核)。
- **边界处待办**:停机 → R2 fid 检查 → 6 台 resume 滚动 → 验证。此前无事;盯 tip 逼近 18,000。

**若 tip 距 18,000 不足 ~2 天而舰队未就绪**(resume 镜像缺失、pin 错),在 #299 上重盖边界章
而非抢高度——超一点只多几天未强制;差一点会让活网停在没有 resume 二进制的边界上。仅在镜像
构建前合法;新高度必须 `≡ 0 (mod 8)`。
