# Remote proving —— Candidate A 真机手机证据，2026-08-24

**状态：首轮真机证据集已完成。不是全网 depth 选择、protocol constant、wallet
integration 或 implementation approval。** 英文权威版：
[`remote-proving-mobile-evidence-2026-08-24.md`](remote-proving-mobile-evidence-2026-08-24.md)。
测量方法与 trust boundary 仍以
[`remote-proving-mobile-benchmark-zh.md`](remote-proving-mobile-benchmark-zh.md) 为准。

20 份原始 JSON 与 SHA-256 manifest 已提交到
[`docs/evidence/remote-auth-mobile/2026-08-24/`](evidence/remote-auth-mobile/2026-08-24/)。

## 1. 范围与设备

独立 research app 在每台设备上对 D12 到 D16 各测两次：

| 平台 | 真机 | OS | 内存 | lab revision | shell revision |
|---|---|---|---:|---|---|
| iOS | iPhone 15 Pro Max（`iPhone16,2`） | iOS 26.6 | 8,025,686,016 B | `ac7681832916c9b9b344052c1fac1f2010c94f34` | `b19e1eb0794a8813950d7fe0482b89f60ca96c76` |
| Android | Solana Mobile Seeker（`seeker; arm64-v8a`） | Android 16 / API 36 | 报告值 7,841,386,496–7,841,513,472 B | `ac7681832916c9b9b344052c1fac1f2010c94f34` | `cefc17a2130dc3abc74823609a9ab3437eede711` |

两端都从 clean source tree 构建，并只安装隔离 benchmark target。使用的是公开、确定性的
research fixture，不是 wallet seed 或 production key。iOS target 未调用 wallet tests 或
Keychain；Android target 不集成 wallet/Keystore，也没有 `INTERNET` permission。

## 2. Evidence 有效性与正确性

全部 20 份保留记录都满足 evidence protocol：

- format 为 `qlab-remote-auth-mobile-bench-v1`，ABI version 1，result 为 152 bytes；
- `source_trees_clean = true`，且记录了明确 lab/shell revisions；
- low-power mode 关闭；
- iOS 起止 thermal 均为 `nominal`，Android 起止 thermal 均为 `none`；
- 每个 platform/depth cell 都有两份完成记录；以及
- 没有 cancel、OS termination，也没有丢弃 throttle/OOM 结果。

每个 depth 的四份跨平台记录都只有一个唯一 `root`、一个唯一 complete-intent digest、
一对唯一 selected indices。静态大小也一致：authorization section 为 7,544 bytes，
每个 slot 的 verifying key 为 1,312 bytes，每个 slot 的 signature 为 2,420 bytes。
因此 D12 到 D16 的跨平台 correctness gate 全部通过。

## 3. Timing 结果

下表是两次保留 run 的算术平均。`total` 包含 address initialization 和一次 synthetic
two-slot spend/verification path；`sign` 是 harness 报告的双签名与 authorization-section
阶段。

| Depth | Leaves | iPhone total | Seeker total | Seeker / iPhone | iPhone sign | Seeker sign |
|---:|---:|---:|---:|---:|---:|---:|
| 12 | 4,096 | 0.320 s | 0.822 s | 2.57× | 0.348 ms | 0.954 ms |
| 13 | 8,192 | 0.624 s | 1.632 s | 2.61× | 0.419 ms | 1.131 ms |
| 14 | 16,384 | 1.226 s | 3.238 s | 2.64× | 0.679 ms | 1.757 ms |
| 15 | 32,768 | 2.443 s | 6.490 s | 2.66× | 0.580 ms | 1.400 ms |
| 16 | 65,536 | 4.988 s | 12.989 s | 2.60× | 0.840 ms | 1.791 ms |

所有 cell 中最大的两次 total-time 差异为 1.97%。Address-leaf generation 约占 total
的 99%。这台 iPhone 的每次 spend sign-plus-verify 低于 1.0 ms，这台 Seeker 低于
2.1 ms；真正影响 UX 的是 initialization，不是 spend。

iOS memory metric 是 process `physical_footprint`，Android 是 PSS；两者的绝对值和
delta 不能直接比较。Android D12 第一次还有 39.4 MiB PSS delta，但后续更高 depth
没有重复，更符合 process/allocator warm-up，而不是随 depth 线性增长的 retained state。
本证据不能推出跨平台 memory ratio。

## 4. 本轮证据支持的裁定

**D16 在这两台实测设备上按 evidence protocol 完成：**两端均完成两次且没有 thermal
escalation，平均为 4.988 s 与 12.989 s。这关闭了“现有 iPhone 15 Pro Max 加一台代表性
supported Android”的首轮 evidence-set 要求。

**这不代表选定 D16 或任何其他 depth 为 network constant。** Seeker 的 12.989 s 平均值
尚未经过获批的 cold address-initialization UX threshold 判断，而且两台设备都不能证明
product supported-device floor 的表现。全网 depth gate 继续开放，直到：

1. Larry 明确最低支持的 iOS/Android hardware 与 OS floor；
2. 在该 floor 上执行同一 clean-revision、每档两次的 D12..D16 protocol；
3. 明确决定可接受的 cold address-initialization latency，以及 background/cancellation UX；
4. Larry 基于合并证据作出 depth 决策。

若 floor 设备失败，正确动作是选择更低 depth 或修改构造，不是把 private authorization
master 上传给 prover。

## 5. 复核命令与未关闭 gate

在 evidence directory 下运行：

```console
shasum -a 256 -c SHA256SUMS
jq -e . raw/*.json
```

原始记录是未取整数值的权威来源。按 repo policy，本次 evidence-only change 没有在本机运行
Rust test。本记录不关闭 production key lifecycle、crash-safe reservation、restore/
multi-device allocation、public-cache transport、wallet integration、AIR/wire/node change、
genesis change 或 real-value launch gate。
