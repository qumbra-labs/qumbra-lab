<!-- English (authoritative on technical detail): after-action-2026-08-15-sync-wall.md -->

# 复盘 — 同步墙与 fleet 滚动（2026-08-15 → 16）

陌生的 genesis joiner 同步不了本网。六轮活体迭代把这堵墙拆了——墙的另一边，轻服务主机和整个共识
fleet 都滚到了首个 CI 构建、frozen-digest 验证过的镜像。

- **frozen digest** `a54e73ce3d1c4fe9984d06b08f99b7577ed1db452b87abd712cf85ce5f3e7b5b`
- **genesis** `138e1524…addb` · **rule domain** `56447169…20b0`
- **fleet** 4 节点、三大洲（us-east-1 · eu-west-1 · ap-southeast-1 · ap-northeast-1）

头条：**从 genesis 起的陌生 joiner 在真 RandomX 下活体跨过 `stip=4912`、一路追到 fleet tip**——墙破了。

---

## 1 — 先是死锁，再是它背后的墙

这天从 **#402** 开始：genesis 同步中的 joiner 拒绝一个历史块，因为它的 finality 落后于 application，锚检查
用了当前（滞后的）finalized 集、而非该块的历史锚集。**PR #403** 修好了——`ChainState` 里一个 O(1) 主链高度
索引撑起的 `SettledHistory` 锚闸 + `anchor_heights_by_root` 反向索引 + 分变体测试。CI **1685/0/8**。

但活体验证在一台 throwaway `t4g.medium` 上过不了 `4912`,**而这个"过不去"才是真正的故事**。前三轮都在改锚
路径。第四轮做了 **perf 剖析 + baseline 对照**:未打补丁的 `main` 逐值复现了同样的 wedge
(`tip=2000 / stip=0 / rback=234`、一条 `pump.dispatch` 慢行)。#402 就此洗清——这墙是预存的 joiner-同步病、
不是补丁造成的。

> **记下来:** 活体 wedge 返工超过一次之前,先跑 baseline 对照 + perf 剖析。CI 绿、单测过都看不见这堵墙,
> 只有从 genesis 起的陌生节点、在真 RandomX 下才照得出来。

## 2 — #412:checkpoint 跳验,一层一层拆

Coordinator 裁决(Larry):本链的信任根是**委员会终局性(quorum 15/21)**,不是逐 header 的 PoW。joiner 可以
信任一个 quorum 验证过的 checkpoint、而不必逐个重算历史 header 的哈希。每一轮活体都逼出下一个瓶颈。

| 层 | 修法 | PR | 效果 |
|---|---|---|---|
| 1 | `submit_header` 在重验已存 header 前先返回 `Duplicate` | #413 | 热路径 RandomX 从 32% 降到 0.74% |
| 2 | `state_fork_point` / `missing_body_hashes` 改用 #402 的 O(1) `main_chain_hash_at`、不再 O(tip−stip) 走链 | #413 | 削掉 fork-point 的 O(N²) |
| 3 | **checkpoint 跳验、缓冲跨度** | #418 | 急取一个 quorum checkpoint(finality → 12344),把上行 header 跨度只做结构检查缓冲在一个累积会话里,frontier 哈希 == checkpoint 块 `B` 时**整段跳 PoW** admit |
| 4 | **追赶 body 取用** | #418 | joiner 在*丢弃自己请求的 body 回答*(`breq` 卡在 2–7);修好后按大 slag 定窗(`breq → 95`) |

`finality.rs` / `committee.rs` 的 quorum 逻辑字节不变。伪造/兄弟 header 若在 `fin` 以下且不在已 admit 的主链上
→ 全验证 → 拒绝。tally 窗口旁路只对**已带完整 quorum、且显式请求**的 checkpoint 生效。

**活体结果:** `stip` 从死卡的 16 一路爬过 4912、追到 fleet tip;合并后 head 的 arm64 acceptance suite 绿;日志里
`admit checkpoint=12472 headers=12472 pow=skipped`。follow-up 立案而非埋掉:**#426** 动态 roster 的弱主观性
(T1)、**#427** 小机上的追赶吞吐。

## 3 — 另两个合并,已裁决

- **#408 → PR #410** —— 陈旧快照静默地代价一次整段 genesis 重放。现在是有类型的拒绝(`Undecodable` /
  `VersionMismatch`,外加被 `.filter()` 丢弃的外来 genesis case)+ 当日志的 finalization 证明快照 tip 在
  finalized 主链上时的近 tip 降级。失败安全地回落全量重放;`open == replay` 与败方分支拒绝都测试锁定。
- **#375 → PR #416** —— halt 中的边界平局败方取回 finalized 兄弟块并 reorg 到它上面。这个解本就存在于运行时
  (#162 rewind + #198/#229 服务 + #371 窗口组合而成),所以 PR 是 `d3_b` 验收锁 + 双语 operator 文档、**零共识
  代码**。装上 arming hard-gate #3(#367)。
- **#409** —— 钱包 ledger 移到叶子 crate(`qlab-ledger`),让非 CLI 壳能渲染:
  `cargo build --release -p qumbra-ffi --target aarch64-apple-ios` 现在通过(依赖图不再拖着 RandomX 的
  C++/cmake)。

## 4 — 轻服务滚动与第一个矿工

链侧的活合并后,**svc0** 刷到 main 构建的镜像,一次一个服务、每个都在公共边读回。

- **cbnode → 878bc444**(deploy #146):`seed.qumbra.org/v1/coinbase → 200`,从 13020 快照恢复、无 genesis 重放。
- **explorer-api → d47a04a0**(deploy #147):#299 的疤又正确渲染了(`divergent=false`、`supply=COMPLETE`)。
  root 到了 **GHCR package ACL**——这是镜像自 08-13 一直陈旧的原因:Actions 推不了,`qumbra-explorer` package
  没给 `qumbra-lab` 仓库 Actions Write。
- **first-miner-journey** —— leg 1 收尾:矿工钱包从活体 seed 边读到 **574 个挖矿块**,与 node1 的四分之一吻合
  (574 实测 vs ~576 预期);deploy #143 关闭。leg 2 由 **#424 proceed-loudly 裁决**解锁(缺 `/v1/coinbase` 只
  缩小输入集→失败安全;与缺 nullifier feed 必须 fail-closed 有本质区别),由矿工线合并;FFI 丢事件的缺口抽成
  **#432**(任何 FFI send 界面上线前必修)。

## 5 — 共识镜像不再手工建

node 镜像没有 CI 发布路径——正是让 explorer 陈旧的同一个缺口。

- **node-image workflow → PR #431** —— drift 告警 + 付费 arm64 runner 上 `confirm=build` 门控的 build+push,两个
  变体(`emission-resume` / `armed`)。**共识把关:** push 前跑 `halt-status`,断言**声明的和从常量重算的**
  frozen digest 都等于 `a54e73ce`,外加按变体的 rule-domain / revision / halt-plan。漂移的共识常量绝对进不了
  registry。builder 纠正了任务书两处:resume 配方还需 `FAUCET_FEATURES`(#397 那次 faucet-armed 的坑),以及
  `armed` 变体天生 rule domain 不同(identifier-bound `Revision::digest`)。
- **#428 → PR #429** —— explorer 的回读用 `"revision":"[0-9a-f]*"`(冒号后无空格)去匹配 buildx 带空格的
  `json.MarshalIndent`,好 push 反而判红。改成 jq 递归下降读两种 OCI 形状(单平台 config 对象 + platform-keyed
  index)并**断言** revision==`GITHUB_SHA`——`unreadable` 与 `mismatch` 现在是两个 verdict。离线 11/11 覆盖 7
  个 fixture,没花付费 run。

## 6 — fleet 滚动 —— 带 gate、一台一台

四台共识节点全部从手工建的 `8407e1a`(f046051)滚到首个 CI 构建、digest 验证的镜像
**`emission-resume-e0b6245` / `c7b8b334`**(deploy #148)。每台之间:fid 一致、slag 0、mready synced。
`node3` 保住 `miner_rkm`;无 genesis 重放。

| 节点 | 恢复 | slag | gate | fid(final) |
|---|---|---|---|---|
| node1 | 快照 @ 13148 | 0 | pass | `482721168520` |
| node2 | 快照 @ 13151 | 0 | pass | `482721168520` |
| node3(矿工) | 回放 19,802 条 | 0 | pass · rkm 保留 | `952f707c7950` |
| node0 | 快照、快 | 0 | pass | `952f707c7950` |

(`fid` 滚动途中前进——`482721…` → `952f707…`——因链在 finalize 新 checkpoint;每次 gate 校的是四台**一致**、
而非等于某个固定值。)

fleet 现在带上这次会话合并的全部重启/重同步加固(#402/#413/#418/#408/#425/#409)。意外重启不再撞它刚拆掉的
genesis-replay/RandomX 墙,几分钟 checkpoint-sync 就回来。**零共识规则改动**——frozen digest `a54e73ce` 全程守住,
由 workflow 门在 push 前断言、并经 `halt-status` 独立验证。

## 台账

**合并(lab):** #403(#402)· #410(#408)· #416(#375)· #418(#412)· #425(#415)· #409(#407)· #429
(#428)· #431(node-image workflow)· #430(#424,矿工线)。
**滚动(deploy):** cbnode 878bc444 · explorer-api d47a04a0 · fleet node0-3 c7b8b334 · deploy PR #146
#147 #148。
**关闭:** #402 · #408 · #375 · #412 · #415 · #424。
**未决 follow-up:** #426(弱主观性 T1)· #427(追赶吞吐)· #432(FFI send 界面门)· #144(重启快照 flush)。

## 教训

**活体 wedge 未经对照即有罪。** CI 绿、单测过都没抓住这堵同步墙——只有从 genesis 起的陌生节点、在真 RandomX 下
抓住了,也只有 baseline 对照告诉我们是哪一层的锅。链上每个 builder 至少纠正过一次任务书;好的那些会停下升级、
而不是发一个貌似对的错补丁。frozen-digest 门现在把"共识镜像上那个绝不能假设的检查"自动化了。
