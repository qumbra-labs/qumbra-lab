# Annulet format 34：冻结记录

*英文版：[`annulet-format-34-freeze.md`](annulet-format-34-freeze.md)。技术细节以英文版为准。*

Lab #937，PR F。format 34 是在交易内付 prover 费用的 Candidate A Annulet：S 和 P 交易带三个输出，第三个输出用 asset 0 付给 prover。它由以下 PR 建成：

| PR | 内容 |
|---|---|
| lab PR #939 | AIR v3 |
| lab PR #940 | 共识 |
| lab PR #941 | witness、bundle、planner |
| lab PR #943 | A′：第三个输出记入 fee bank |
| lab PR #944 | 内核 |
| lab PR #946 | 服务 |
| lab PR #947 | 导入工具 |

本文记录冻结了哪些值、每个值钉在哪里、每个钉是怎么得出的。

设计侧的说明在 design 仓库的 L2 roadmap 笔记里，包括残余问题，以及 D4、D5 的实际落地情况。

## "冻结"的含义

下表每一项都已经有东西在依赖：format 34 的节点、钱包内核、prover 服务或创世。**改动其中任何一项，都要开一个新的 format 版本、做一个新的创世，而不是修改 34。**

每个值都存在两处：
1. 它的生产常量；
2. `format_34_is_frozen`（`crates/qlab-bench/src/freeze34.rs`）里写死的字面量。

改动时两处都得手工改，测试会报出是哪一项变了。这个测试放在 `qlab-bench`，是因为这个 crate 已经直接依赖所有持有这些值的 crate，放在这里不需要新增依赖。

## 冻结了什么

基准是 lab main `5a719644`。车道 run 38589728298（201/3671/0/17）验过下面每一个钉。

| 项目 | 值 | 钉在哪里 | 怎么得出 |
|---|---|---|---|
| 创世 format 版本 | 34 ↔ `(Annulet, CandidateAV3)` | `qlab-devnet/src/forms.rs`（`ANNULET_AUTH_V3_GENESIS_FORMAT_VERSION`、`annulet_forms_of_genesis_format_version`） | lab PR #940 |
| S/P 输出数 | 3（R 仍是 2） | `qlab-devnet/src/forms.rs`（`L2AuthForm::sp_outputs`） | lab PR #940 |
| body 和创世 body 的域 | v3 的两个域 | `qlab-devnet/src/annulet.rs`（`BODY_PREIMAGE_DOMAIN_ANNULET_V3`、`GENESIS_BODY_DOMAIN_ANNULET_V3`），测试 `format_34_is_frozen` | lab PR #940 |
| served wire form | 字节 6 | `qlab-p2p/src/served.rs`（`wire_form_byte`）、`qlab-p2p/src/compact.rs`（`WireForm::ANNULET_AUTH_V3`） | lab PR #940 |
| 证明 bundle 版本（三输出） | 2 | `qlab-l2spend/src/bundle.rs`（`BUNDLE_VERSION_THREE_OUTPUTS`） | lab PR #941 |
| S v3 shape digest | `2b65c9d45b626dcbfc02bb49ae9574d5724d87a577a759b0a297ab1e0da015b8` | `qlab-l2/src/v3.rs`（`SHAPE_S_DIGEST_V3`），由 `l2_v3_shape_digests_are_pinned` 重算 | `3d987c9e` 上的 `l2_goldens`（A′，lab PR #943） |
| P v3 shape digest | `925d542ef83f4f2910394c21c30842bd64f5c17c32fba628fa6f16434b469b34` | `qlab-l2/src/v3.rs`（`SHAPE_P_DIGEST_V3`） | 同上 |
| v3 的常量摘要、约束摘要和约束条数 | `v3::PINS_V3` | `qlab-l2/src/v3.rs`，测试 `l2_v3_shape_digests_are_pinned` | 同上 |
| devnet_v3 创世 | `7673e01f2902344b902e40ad498e3bf4368e355dffa277669c947fbda700f65e`，5,241 B | `qumbra-node/src/annulet_genesis.rs`（`DEVNET_V3_GENESIS_HASH`） | 在 `d8ff3606` 上跑两次 `qumbra-node genesis annulet-devnet --v3`；在 `5a719644` 上复核（见下节） |
| devnet_v3 rehearsal 创世 | `439de6fca8be1efb78996c0a0906e33ae43d854f50d5e299d0dfe6049b541fb5`，5,251 B | 同上（`DEVNET_V3_REHEARSAL_GENESIS_HASH`） | `--v3 --rehearsal`，同一批运行 |
| detaudit v3 分支 | `s3v3` 和 `p3v3`，各覆盖 `house`、`exact`、`fee-bank` 三种 fixture | `qlab-bench/src/detaudit.rs` | lab PR #939、lab PR #943 |

**format 34 没有改动、并在 5a719644 上复核过的：**
- v2 devnet `2bd53cd1…` 及其 rehearsal `e21a7b08…`；
- v1 devnet `00c70e55…`；
- fixture `85dd805d…`。

**`.github/` 里没有任何 format 34 的值。** 那里的冻结摘要和规则域属于 L1，T1、T2 的创世哈希也是。

## 在 5a719644 上复核创世

每种创世构造用 `qumbra-node genesis annulet-devnet [--v2 | --v3] [--rehearsal]` 各跑两次，每次都是新进程。每种构造的两次输出逐字节相同，并且都等于各自的钉：

| 构造 | 创世哈希 | 文件 sha256 | 大小 |
|---|---|---|---|
| v1 devnet | `00c70e55c95e8f6519e956884bf6ffc56476fe1b3cd196983a46e1f4221d7e03` | `85af2662e244b6e61f3dfc231b7b7e361eee9a82f290b56da26268c2f7f13be3` | 5,238 B |
| v2 devnet | `2bd53cd149cd5e8b43917b468c82249dd41c1602814b1f24ef39e61cafb3d13a` | `9a276e7debf5a7bda7d375c02d987ec594a53f7d2267db972b04e053c9fe2139` | 5,241 B |
| v2 rehearsal | `e21a7b089927dbede8171744675830bd60f8f3b854617421a9fcf8e4728fee97` | `cd49f691ba811de4d2c81fb5369800d0c2d28b1604c633b7147b7780d2b61e1e` | 5,251 B |
| v3 devnet | `7673e01f2902344b902e40ad498e3bf4368e355dffa277669c947fbda700f65e` | `2ada7f470727454dc9b03d243e8e0d696e0360a3672bb43fe3a1fe434c709d33` | 5,241 B |
| v3 rehearsal | `439de6fca8be1efb78996c0a0906e33ae43d854f50d5e299d0dfe6049b541fb5` | `0f9a32dac72e8205916aec09daa50bfa21da1845c48ffdb52571348b407b6b77` | 5,251 B |

v1 devnet 没有 rehearsal 构造。fixture 创世（`85dd805d…`）只在测试里构造，它的钉测试在同一条车道上。

## AIR 的实测

o3f 箱子复测：prover-1（r7g.2xlarge，64 GiB，Ubuntu 24.04 arm64，rustc 1.99.0），lab main `5a719644`，主机空载，2026-10-15 06:18–07:23 UTC。脚本 `run-o3f-box.sh`；tarball sha256 `1ab0b639a822c3be621fa8eebdf758d013b967247baff77891fdba3ffc0527bc`。八项全部退出码 0。

**证明**（`l2shape`，b4/q45 车道，log height 20；峰值内存和耗时取自进程外的 `/usr/bin/time -v`，证明时间是 bench 三次取最好）：

| 形状 | 实例 | 宽度 | 峰值内存（kB） | 耗时 | 证明（ms） | 验证（ms） | 证明大小（KB） |
|---|---|---|---|---|---|---|---|
| P | fee bank（o3f = 1），第 1 次 | 871 | 33,701,756 | 2:55.87 | 55,774 | 12.2 | 470.5 |
| P | fee bank（o3f = 1），第 2 次 | 871 | 33,701,756 | 2:58.08 | 56,852 | 12.0 | 470.2 |
| P | exact（o3f = 0） | 871 | 33,701,796 | 2:57.28 | 55,603 | 12.1 | 470.3 |
| S | fee bank（o3f = 1），第 1 次 | 788 | 30,981,600 | 2:42.40 | 51,552 | 11.5 | 449.3 |
| S | fee bank（o3f = 1），第 2 次 | 788 | 30,981,388 | 2:41.44 | 51,413 | 11.7 | 449.5 |
| S | exact（o3f = 0） | 788 | 30,981,400 | 2:41.11 | 51,190 | 11.8 | 449.3 |

同一个 AIR 上，fee bank 相对 exact 没有可测的代价：峰值内存差在 0.001 % 以内，耗时差在 1.5 % 以内。和 lab PR #939 在同机型上的 o3f 之前的箱子（2026-10-08，宽度 780/863）相比，o3f 让 S 和 P 的峰值内存各多 0.8 %，证明时间不变。

**确定性 census**（fee-bank fixture；只写汇总）：

| AIR | 单元格 | 已定 | 未定的 public value | 耗时 | 峰值内存（kB） |
|---|---|---|---|---|---|
| s3v3 | 826,277,888 | 728,755,477 | **0** | 32:06 | 23,476,344 |
| p3v3（`--no-pv-inputs --cr-premise`） | 913,309,696 | 832,201,994 | 55，**全部是 `q = 1` 的记账自由度**（见下） | 45:55 | 27,539,712 |

**p3v3 的结论。** fee-bank fixture 花两个同资产的输入（`q = 1`）。它的 census 推不出来的 public value，包括输出承诺在内，全部属于 i758 census 在 P3 merge 上发现的那种记账自由度（`docs/i758-determination-census.md`，P3）：每个输出记在哪一个余额行上。收口的方法和 i758 相同，用的是同一台主机、同一个 sha、同样前提的后续运行（2026-10-15；tarball sha256 `2d9de314497e70d8e5ccddb2a9b11fcfdd438c727b51be840560e03cb16fe770` 和 `bdce8f9528b9a79dcaea9ae9c0fcee4943773eb5fcfd194a0310809972e462bb`）：
- 把输出记账开关 `o1a`/`o2a`/`o3a` 声明为源（`--pin-sel2`，i758 的诊断前提）后，只剩 3 个 public value 推不出来，和 i758 的 P3 merge 在同一前提下的 3 个相同。输出承诺都被确定。
- 不固定时，翻转 `o1a`、翻转 `o2a` 各自都确认为**可满足，且没有任何 public value 改动**；对修复后的完整 trace 做的独立 p3 检查，两次都通过（1:14:46 和 1:13:32，峰值 30,594,636 kB）。
- `o3a` 在这里不是自由的：AIR 强制 `o3f · o3a = 0`，而 fee-bank fixture 的 `o3f = 1`。
- 之前有一次直接针对输出承诺的确认，挑中的是一个 dummy 角色的见证根，在其他根被固定时得到 UNSAT。这不构成反驳，所以不计入。

从约束本身也能得出同样的结论。开关只改变一笔金额在两个余额行之间怎么分。两行相加后，每步增加 `(AG_IN1 + AG_IN2 − AG_O1 − AG_O2 − AG_O3 + SF3) · pw · v`，`SG₀`、`SG₁`、`SG₃` 全部抵消。在 `q` 下，close 只读相加后的那条链。这就是 i758 的 `o1a` 论证，加上第三个输出的几项。

## 本次不冻结的

- **生产创世和 prover pin。** format 34 的生产创世在割接时铸出；割接 runbook 加上它的 prover pin（`qumbra-wallet/src/prover_pins.rs` 的 `PINS`，在那之前为空），并发布内核。
- **价格。** 属于部署配置，不超过 pin 里的上限。
- **token 退役**（#937 D6）。在割接之后。
- **割接演练。** 在 prover-1 上用真实 ingress 跑（`X-Qumbra-Client-IP` 由 Caddy 加），由内核客户端驱动：先对 `devnet_v3_rehearsal`，再对生产创世。服务路径上 S 和 P 的实测数字也出自这次演练。
- **CLI 远程证明客户端。** 目前没有，`qumbra-wallet` 没有 `--prover`。如果需要，另开一个小 PR。

prover 服务的协议版本（`ANNULET_PROTOCOL_VERSION = 1`）不变。format 33 和 34 的服务已经可以靠 `/v2/annulet/info` 里的 `genesis_hash` 区分，34 上的两输出 bundle 也会被按名拒绝。

## 另见

- [`prover-service-annulet-zh.md`](prover-service-annulet-zh.md)：format 34 上的服务。
- [`prover-payee-wallet-zh.md`](prover-payee-wallet-zh.md)：导入付费台账。
