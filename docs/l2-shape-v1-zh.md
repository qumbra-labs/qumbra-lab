# L2 shape v1 —— shape 已冻结，lane 暂定

> [English](l2-shape-v1.md)（技术细节以英文版为准）· 跟踪：lab issue #704（l2-roadmap A1）· 电路：lab PR #701 / issue #700（W3）· crate：`crates/qlab-l2`

**状态（2026-09-23）：** L2 的两个交易 shape，**S** 和 **P**，已按 v1 冻结。它们的 program、几何、公共值布局、note 块、电路内的域常量和约束集，都在 `qlab-l2` 和 `qlab-note` 里按名字钉住了。**lane 没有冻结**：协调者那边对 lane 的 PCS 配置有一项审查还在进行，`L2_CFG_PROVISIONAL` 在此期间保持暂定。这项审查可能改变证明的线上字节而不动 AIR，所以**证明字节数一律不钉**。

## 1. 冻结了什么

| 对象 | v1 值 | 由谁钉住 |
|---|---|---|
| shape S 几何 | 702 列 · 120 个置换 · 2^19 行 · 最大约束次数 4（4 个商块）· 100 个公共值 | `l2_shape_geometry_is_locked`；`qlab-air` 的 `l2_trace_width_is_read_off_the_matrix`、`l2_quotient_degree_matches_the_l1` |
| shape P 几何 | **778** 列 · **214** 个置换（环 216 槽）· 2^20 行 · 次数 4 · 112 个公共值 | `l2_shape_geometry_is_locked`；`qlab-air` 的 `l2p_trace_width_is_read_off_the_matrix`、`l2p_quotient_degree_matches_the_l1`、`l2p_program_geometry` |
| 公共值布局 | `anchor` 0 · `nf₁` 16 · `nf₂` 32 · `cm₁` 48 · `cm₂` 64 · `fee` 80（4 个 16 位块）· `registry_root` 84 · 仅 P：`vPublic₁` 100、`vPublic₂` 106（各为 `redeem`、`amount` 的 4 个 16 位块、`vpa`） | `l2_shape_geometry_is_locked`、`l2_golden_pv_vectors` |
| program | 每个槽的 5 位角色码；所有构造器产出同一个 program，所以验证者用的 AIR 只取决于 shape | `l2_verifier_air_is_instance_independent`；shape 摘要 |
| note 块 | `cm = H(value ‖ asset ‖ rkm ‖ ρ ‖ rseed)`；112 字节明文 `value(8 LE) ‖ asset(8 LE) ‖ rkm ‖ ρ ‖ rseed` | `qlab-note` 的 `l2_golden_note_block`（字面值在 Rust 之外独立算出）、`l2_commitment_matches_qlab_air_build_bucket_l2` |
| 发现载荷 | `L2_PAYLOAD_LEN = 128`（112 字节 note + 16 字节 tag） | `qlab-note` 的 `l2_payload_len_is_128` |
| 电路内域常量（P） | `D_I` = lane 4 第 7 位（`issuer_key = H(isk ‖ D_I)`）· `D_CRED` = lane 4 第 15 位（`cred = H(rkm ‖ D_CRED)`）· **`D_FRZ` = lane 4 第 31 位**（冻结键 `K = H(rkm ‖ D_FRZ)`） | shape 摘要里的已知答案；`l2p_policy_blocks_match_reference` |
| 资产 id 空间 | 16 位注册表下标（16..63 位强制为 0）；注册表深度 16 | `l2_asset_id_is_a_16_bit_registry_index`；`l2_shape_geometry_is_locked` |
| 树深度 | 承诺树 32 · 注册表 16 · 冻结树 20（有序索引树，按 `K` 建键）· 白名单 20 | shape 摘要 |
| **shape 摘要** | S `7a6391bc98eed26b4bff7aaaa987f7d6ef657e27ad50746c9c519bcabdae6670` · P `ad53d40e7d5ffd8235b701fab16856f428790b7ba33efc8915abe625f1bacaff` | `l2_shape_digests_are_pinned` |

**shape 摘要**（`qlab_l2::digest`）是 `Keccak-256(b"qumbra:l2:shape:v1" ‖ tag ‖ 常量 ‖ 约束)`：
- **常量**部分：几何、公共值布局、标准 program、各树深度、mode/flag 取值，外加电路所镜像的每个主机侧哈希的已知答案。域常量是哈希块里的 lane/位位置，不是具名常量，所以通过这些输出来钉，而不是再手抄一遍。
- **约束**部分：对 Plonky3 符号约束集做的结构化内容哈希——S 有 1,057 条约束，P 有 1,270 条。哪怕一处约束改动没碰任何常量，摘要也会变。
- 测试里会把摘要算两遍，以此确认它是确定性的。
- **Plonky3 升级导致摘要变化，也算一次冻结事件。** 重新钉值必须经协调者同意。

### 1.1 相对 W3 的 shape P 唯一的改动：冻结键改为哈希

W3 构建的 shape P，冻结树按**原始 `rkm`** 建键。#704 的裁定（Q1）把键换成了 **`K = H(rkm ‖ D_FRZ)`**：
- 每个输入在 `ARKM` 和 `AFRZ` 之间新增一个置换 `AFKEY`（角色码 22），它吸收链上传来的 `rkm` 并带上 `D_FRZ`。
- `AFRZ` 边界行上的两次逐位比较，现在拿 `K` 和低位叶子比。
- 第三个等式库的 `+rkm` 分支挪到 `AFKEY` 的边界行，所以 `rkm` 的三次推导仍然互相绑定。

代价：置换数 +2（212 → 214，仍在 2^20 以内），列数 +4（774 → 778），分别是一个环 limb、一个选择子、一个注入、一个门控。约束次数不变。

为什么值得改：按原始键，公开的冻结名单会把每个被冻结地址的"所有者那一半"直接交给读者；按哈希键，读者对自己手里没有的地址一无所知。手里有地址的人照样可以查，这和公开制裁名单的披露程度一样。

变异检查是 `l2p_neg_raw_rkm_keyed_witness`：一片真实存在的叶子，恰好把被冻结持有人的*原始* `rkm` 夹在中间——W3 的电路会接受它，现在必须 UNSAT。

## 2. 没有冻结什么

| 对象 | 状态 |
|---|---|
| lane `L2_CFG_PROVISIONAL` = b4/q43/g22/fp16/a16 | **暂定**。只在 `qlab_l2::make_config_l2()` 一处构建，审查结论落地时只改这一处。`l2_cfg_provisional_is_value_locked` 防的是*意外*改动。为什么是 b4：两个 shape 都是 4 次（4 个商块），而 Plonky3 0.6.1 在 b2 下验证不了 4 个商块的 AIR（`l2shape_b2_is_not_a_lane_for_a_degree_4_air`）。q43/g22 按 2197 修正口径是 101.6 位。 |
| 证明线上字节 | **不钉。** 没有 `WIRE_BYTES_S/P` 常量，也没有字节测试；下面的数字只是测量值。 |
| 固定实例的证明字节 | 按设计永远不钉。Plonky3 的 grind 见证由并行的 `find_any` 找出，所有查询下标都在它之后抽取，所以同一个实例在不同线程调度下会得到不同的证明。钉住的是公共值向量和 note 块。 |

## 3. 暂定 lane 下的测量（W3 记录，不是钉值）

Apple M5 Max / 36 GiB，release 二进制直接跑在 `scripts/rig run` 里的 `/usr/bin/time -l` 下，无 swap；出处 `docs/w3-run1.md` … `w3-run4.md`。

| shape | lane | 列 | log_height | 证明耗时 | 峰值内存 | 证明（bincode 定长） |
|---|---|---|---|---|---|---|
| S（rev `8a20234`） | b4/q43/g22 | 702 | 19 | 1.52 s | 6.80 GB | 285,605 B |
| P（rev `20723c9`，**774 列，加 `AFKEY` 之前**） | b4/q43/g22 | 774 | 20 | 3.56–3.76 s | 15.06–15.11 GB | 312,677 B |
| P v1（778 列） | b4/q43/g22 | 778 | 20 | **待重测（协调者的 rig）** | — | — |

**shape S 在 16 GB 级机器上能证明，shape P 在 b4 下需要 32 GB 级机器。** P 要 15.1 GB，装了操作系统的 16 GB 笔记本放不下。

## 4. A1 新增的测试

`qlab-l2`：`l2_cfg_provisional_is_value_locked`、`l2_crate_deps_are_exactly_air_and_consensus`、`l2_shape_geometry_is_locked`、`l2_verifier_air_is_instance_independent`、`l2_prove_verify_roundtrip_s`、`l2_prove_verify_roundtrip_p`、`l2_shape_digests_are_pinned`、`l2_golden_pv_vectors`。`qlab-note`：`l2_payload_len_is_128`、`l2_golden_note_block`。`qlab-air`：`l2p_neg_raw_rkm_keyed_witness`。已有测试按 P v1 更新，没有删除任何测试。
