# 2026-08-05 之夜:一次幻影分叉、一次烧槽停摆,与签名滞后修复

> [English](incident-2026-08-05-finality-night.md)

**范围:WAN,活的 T0 网(创世 `138e1524…addb`)。** 一个晚上产生了两起事故——一起从未
发生,一起真实发生——并在天亮前完成了一个共识活性修复的构建、验收与四台上线。这是
findings 记录;引用的全部产物在文末列出。由执行修复弧线的 session 撰写;它当晚自己的
错误也是记录的一部分,依 no-silent-divergence 惯例。

## 时间线(+08)

| 时间 | 事件 |
|---|---|
| 19:32–19:37 | 网无人值守地穿越**第一个委员会 epoch 边界**(块 1152):边界前 final 冻结于 1120 约 40 分钟(已知形状),然后一步 finalize 到 1152,epoch 0→1 |
| ~21:5x | Coordinator session 执行 org 迁移 roll(镜像引用 `lai3d` → `qumbra-labs`),误判 node3 分叉,触发 R2,冻结 roll,提交 **#268** |
| 22:02–22:07 | 独立分析(本 session):**分叉从未存在**——容器根本没被重建(roll 在主机侧是 no-op:钉死的 compose 文件从未 rsync 到主机),"分叉"读数(`tip=1676`、`fid=e9de…`、`epoch=0`)在任何日志中不存在,且在 25 小时龄的链上算术不可能;`fid` 还被误读为链身份 |
| 22:14 | Larry:先查 no-op 原因,再重跑 roll |
| 22:18–22:27 | 重跑(rsync 路径,正确):四个容器 9 分钟内相继重建,每台按 `slag=0` + fid 过门——"final 在推进"这一条**在一个 10 分钟 cadence 内不可验证** |
| ~22:31 | 最后一次重启数分钟后、mesh 尚在重建时,tip 到达检查点 slot 1296:四个不同的 1296 候选块,**21 把钥匙各签本地变体——slot 四路烧毁**(#223 机制的车队级放大) |
| 22:20–23:11 | **Finality 停摆 51 分钟**(final 钉在 1288)。slot 1304(4 变体)、1312(3 变体)接连烧毁;mesh 恢复后 **1320 以 2 变体 finalize**——自愈,无人干预 |
| 22:5x | 本 session 的分析称卡死*永久*(**错**——从 #204 查询路径外推,并把未打印的开放 round 读成不存在;proposer cursor 实际上会走过每个 cadence slot),在该前提上提交 **#269** |
| 23:15 | 测得痊愈状态的同一分钟发布自我纠正并给 #269 改题;deploy 侧记录同样方式更正(所有原文保留) |
| 23:37–00:42 | Larry:修。**签名滞后建成**:`CHECKPOINT_SIGN_HYSTERESIS_BLOCKS = 2`,slot 在 `tip ≥ S+2` 才签;slot 0(创世被 hash 钉死)与 halt 边界(#74 要求 H 的检查点)豁免。新增一个测试;十处既有测试更新(挖矿循环 `+2`,无断言被削弱)。**验收 1229/0/1** 无过滤,对账(1228 + 1) |
| 00:43–00:47 | lab PR #270 合入(`5f4123e`);**t0-wan-12** 从干净 detached 树构建(provenance 逐步核实——124 个 crate 实际编译、revision 标签读回),推送,digest 钉入 deploy compose(PR #75) |
| 00:48–01:24 | **按修正后的门滚动**(deploy PR #74:每台重启后必须有一次**新的** finalize——当晚从烧槽中写出,此处首次执行):node1→node2→node3→node0,finality **单调 1392 → 1432,跨五个检查点 slot,零烧毁** |

早晨核查(07:07):final=1696,fid 一致,自滚动以来每个采样 `slag=0 schain=main`——
drill 的 24 小时安静窗(01:24 重新起算)干净累积中。

## 缺陷,精确表述

三个事实组合成了停摆:

1. `try_checkpoint` 在 **`tip == S` 的瞬间**签署每个 cadence slot S——正是竞争性 S 块
   存在的窗口。#223 早已点名其单 slot 代价;一个重启密集窗口(9 分钟四次重建,mesh
   `peers=0→3→5`)让它**连烧三个 slot**,各 21/21 票,无变体达 quorum 15。
2. 票按 slot 不可变**是设计**(`FinalizerState::authorize` 拒绝在已签 slot 上签不同
   检查点,持久化)——永不改签守卫全程正确工作,不是缺陷;任何时刻都没有错误 finalize。
3. 恢复**靠运气而非设计**:proposer cursor 确实会走后续 slot(所以"永久卡死"是错的),
   但每个新 slot 又在自己的竞争窗口被签,恢复只能等一个传播恰好紧致的 round
   (51 分钟里变体 4→4→3→2)。

修复消除了 (1):两块埋深之后,slot 块已沉淀,钥匙才承诺。常数代价 150 秒 finality
延迟。参数为 devnet 级、testnet 可调;深于 2 块的竞争仍可能分裂一个 slot——这一类被
收窄,而非消灭。

## 三条教训,具名

1. **承重数字必须连同原始命令与输出一起抵达。** #268 的表格一条都没带;读数无锚
   (提交它的 session 当晚已自录两次批量输出误读),而那个 R2 STOP 所依据的数字,一行
   算术——tip 对 链龄×出块率——即可否证。这是 07-31 "`ROUND lines: 0`" 失败家族的新装。
2. **"不可能"的分析需要生产调用方,而不是一个貌似合理的调用方。** "永久卡死"从 #204
   *查询*路径外推 `next_checkpoint_height`,并把未打印的(开放)round 当作不存在。
   纠正在反证测得后几分钟内落地——但错误结论已驱动了一晚的恢复选项规划。值得保留的
   对称性:**同一晚两个 session 各自盖出了自信的错误结论**——一个源于幻影证据,一个
   源于不完整的代码阅读——而两者被同一套纪律逮住:带日期更正,原文保留。
3. **门必须在它所门控的时间尺度上可验证。** "final= 在推进"在一个 10 分钟 cadence 内
   读不出来,于是时间压力下退化为只读那两个*能*读的门——四次重启 9 分钟落地即由此而来。
   修正后的门(每台重启后一次**新的** finalize)按构造可检验,首次执行跨五个检查点
   slot 毫发无损。

## 代价与所得

约 51 分钟 finality 停摆(自愈)、约 4 个 session 小时的夜间工作、12 小时内五次全车队
重启。换来:这条网**第一次无伤 finality 地完成一次滚动**、对 T0 网迄今最尖锐缺陷类的
活性修复、一个让该缺陷触发条件在例行操作中不可达的操作门,以及——计划外的——一次
committee stall → recovery 的全弧线实弹观测,恰是 drill D3 的主题。

## 产物

- lab [#268](https://github.com/qumbra-labs/qumbra-lab/issues/268)(幻影;分析在帖内)·
  [#269](https://github.com/qumbra-labs/qumbra-lab/issues/269)(缺陷;自我纠正在帖内)·
  [PR #270](https://github.com/qumbra-labs/qumbra-lab/pull/270)(修复;关闭 #269)
- deploy [PR #72](https://github.com/qumbra-labs/qumbra-deploy/pull/72)(事故记录)·
  [#73](https://github.com/qumbra-labs/qumbra-deploy/pull/73)(带日期更正)·
  [#74](https://github.com/qumbra-labs/qumbra-deploy/pull/74)(门修正)·
  [#75](https://github.com/qumbra-labs/qumbra-deploy/pull/75)(t0-wan-12 pin)·
  [#76](https://github.com/qumbra-labs/qumbra-deploy/pull/76)(roll 记录)
- `qumbra-deploy/tasks/roll-org-ref-and-finality-wedge-2026-08-05.md` ·
  `tasks/roll-t0-wan-12-2026-08-06.md` · `qumbra-ops/image-build-t0-wan-12.log` ·
  sampler `qumbra-ops/t0-138e1524.log`(iter ~256–290 覆盖整条弧线)
