# W3 第一阶段 — shape S 实测，第一跑（lab #700，PR #701）

> [English](w3-run1.md)（技术细节以英文版为准）· 复现：[`w3-run2-zh.md`](w3-run2-zh.md) · 构建笔记：[`w3-build-notes.md`](w3-build-notes.md)

- 硬件：Apple M5 Max，36 GiB RAM（18 核）
- 系统：macOS 27.0
- qumbra-lab 版本：`8a20234`（分支 `claude/w3-l2-shapes`，每次运行 `scripts/rig` 的横幅均显示树 CLEAN）
- 证明器：Plonky3 0.6.1（`Cargo.lock` 锁定）
- 电源：AC，电池 80 % 未充电，未观察到热压；**机器共享** — 起跑时其他驻留进程 active + wired ≈ 16.3 GB（vm_stat）
- 日期：2026-09-22，18:43–18:47 +08（第一跑）；锁持有者 `QUM-181`
- AIR：`qlab_air::l2::L2ShapeSAir` — **702 列** × 3072 行/perm，40 个周期列，**PV_LEN 100**，约束最高次数 **4**，**4 个商块**（全部由 bench 启动时从矩阵 / Plonky3 符号求值读出，并由 `l2_trace_width_is_read_off_the_matrix` / `l2_quotient_degree_matches_the_l1` 锁定）
- 每格：prove / verify = 进程内 3 次取最优；证明字节 = postcard 与 bincode 定长（线格式代理）；峰值 `phys_footprint` 与最大 RSS 来自直接包住 **release 二进制** 的 `/usr/bin/time -l`，每进程一个 shape × 一条 lane，置于 `scripts/rig run` 内；每行断言 swap 为 0

## 调用（逐字；`./w3-logs/measure.sh <tag> <shape> <lane>` 为封装）

```sh
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape s       --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape mock118 --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape s       --only b8 --power AC
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape mock118 --only b8 --power AC
# 金丝雀（#700）：2^19 b4 峰值 footprint 6.78 GB × 2 = 13.6 GB < 32 GB → 允许启动 2^20 lane
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape s20     --only b4 --power AC
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- /usr/bin/time -l ./target/release/qlab-bench l2shape --shape mock240 --only b4 --power AC
```

`--only b4` 选 `b4/q43/g22/fp16/a16`（发货 leaf 点，`m4treerec::AGG_CFG`）；`--only b8` 选 `b8/q29/g22/fp16/a16`。b16 lane 与 2^20 b8 lane **未运行**（第 0 阶段裁决 §5.3：重 lane 推迟）。

## 第一跑

| shape | lane | perms（程序/容量） | 宽度 | log_height | 最高次 | prove ms | verify ms | 定长 B | postcard B | 峰值 footprint GB | 最大 RSS GB | swaps | real s | user s | sys s | 指令数 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **shape S** | b4/q43/g22/fp16/a16 | 120/170 | 702 | 19 | 4 | **1516.8** | 20.6 | **285,605** | 331,718 | **6.782** | 7.067 | 0 | 5.90 | 61.61 | 6.62 | 9.77e11 |
| **shape S** | b8/q29/g22/fp16/a16 | 120/170 | 702 | 19 | 4 | **2582.7** | 18.3 | **206,221** | 239,801 | **13.756** | 13.755 | 0 | 8.91 | 102.84 | 11.87 | 1.55e12 |
| shape S @ 2^20（P 高度代理） | b4/q43/g22/fp16/a16 | 120/341 | 702 | 20 | 4 | 3192.2 | 23.1 | 297,989 | 346,567 | 14.111 | 14.107 | 0 | 11.50 | 130.39 | 10.38 | 1.89e12 |
| MOCK 118 @ 2^19 | b4/q43/g22/fp16/a16 | 118/170 | 702 | 19 | 4 | 1558.4 | 21.2 | 285,605 | 328,697 | 6.782 | 7.067 | 0 | 5.67 | 61.88 | 6.65 | 9.54e11 |
| MOCK 118 @ 2^19 | b8/q29/g22/fp16/a16 | 118/170 | 702 | 19 | 4 | 2476.4 | 17.7 | 206,221 | 237,535 | 13.477 | 13.758 | 0 | 8.50 | 99.13 | 11.41 | 1.44e12 |
| MOCK 118 程序 @ 2^20（"240"） | b4/q43/g22/fp16/a16 | 118/341 | 702 | 20 | 4 | 3213.4 | 23.6 | 297,989 | 343,567 | 13.562 | 14.110 | 0 | 11.53 | 130.84 | 9.96 | 1.85e12 |

MOCK 行标为 MOCK，不作门槛（#700 第 0 阶段）。"perms 程序/容量" = 含预热槽的程序 perm 数 / 该高度可容纳的 perm 数。

## 数字说明

1. **shape S 在 b4：峰值 footprint 6.78 GB，prove 1.52 s，定长 285,605 B。** 相对任务书预登记（~5 GB / ~470 KB）：RAM +36 %，字节 −39 % —— 任务书把字节按行数线性缩放，但证明大小随 `log_height` 与宽度（查询路径长度）增长而非随行数；定长 278.9 KB 对比 M3 b4 点（617 × 2^18）的 236.4 KB 为 +18 %。相对第 0 阶段贴出的 LDE 律投影（5.9 GB），footprint **+15 %**；b8 同样超出（13.76 对 11.8，+17 %），2^20 亦然（13.6–14.1 对 11.8，+15–20 %）。**LDE 律在此几何下低估约 15 %，且该超额在 M3 点上看不到**（投影 2.59 / 实测 2.6）。以下所有 shape P 投影均带入该系数。
2. **mock 在同高度下与 shape S 各列均在 2 % 内复现** —— 理应如此，证明器定价的是宽度与高度；2 个 perm 与 registry 角色是噪声。mock 的任务（在真电路之前给 2^20 定价）已完成：2^20 b4 机器需要 **13.6–14.1 GB**。
3. **shape P 在 b4，按实测 2^20 孪生重新投影**（第 0 阶段裁决 §3 重登记为 13–14 GB；本条取代之）：`s20 b4` 在宽度 702 实测 13.9–14.1 GB；shape P 投影约 790 列（`w3-build-notes.md` §census，gadget (a)）；按宽度线性缩放（LDE 律与 M3 → S 差值唯一支持的缩放），**P b4 ≈ 13.9 × 790/702 = 15.6 GB 至 14.1 × 790/702 = 15.9 GB，对 16 GB 门槛余量 1–3 %，而非 15 %。** prove 时间：s20 b4 3.19 s → P ≈ 3.6 s，对 20 s 余量充足。包络的 RAM 侧是第 2 阶段全部风险，**b2 是杠杆**（LDE 减半：~8 GB 级），不是树深。不构成 STOP：尚无越界，且 ≤ 2× 的偏差有指定的一轮调优。
4. **b8 用 b4 的 2.0× RAM 换 −28 % 字节**（13.76 对 6.78 GB；206 KB 对 286 KB），prove +70 %。按设计自身准则（§2.5：L2 lane 按证明者 RAM 而非字节选取 —— 其证明会被聚合并剪除）**b4 即 lane**，这是首次两组数据齐备的实测结论。
5. **verify 18–24 ms**；postcard 字节含 ±0.05 % 实例依赖（varint），定长字节在相同几何下跨运行、跨 shape 逐字节一致（285,605 / 206,221 / 297,989 B）。
6. **每行 swap 为零**，六行 `sys` 均为 `user` 的 10–12 %（污染特征 —— `sys` 数倍膨胀而指令数持平 —— 第一跑不存在；`w3-run2-zh.md` 记录了两个例外行）。

## 复现状态（±1 % 规则，#700）— 完整对比见 `w3-run2-zh.md`

| 行 | 第一跑 | 第二跑 | 第三/四样本 | ±1 % 内？ |
|---|---|---|---|---|
| S b4 footprint | 6.782 | 6.797 | — | ✅ 0.2 % |
| S b8 footprint | 13.756 | 13.479 | 第三跑：**13.758** | ✅ 第一、三跑（0.02 %）；第二跑落在 mock 的值 13.48 |
| s20 b4 footprint | 14.111 | 13.895 | 第三跑 13.562，第四跑 **13.892** | ✅ 第二、四跑（0.02 %）；四个样本取三个离散值（13.56 / 13.89 / 14.11）；**四次最大 RSS 均为 14.107–14.111 GB** |
| mock118 b4 / b8、mock240 b4 footprint | 6.782 / 13.477 / 13.562 | 6.783 / 13.477 / 13.563 | — | ✅ 到 MB |

2^20 几何带出的需求数字取**观测最大值 14.11 GB**（第一跑 footprint；四个样本的最大 RSS）。度量发现，记入 rig 文档：此规模下压缩器从不介入（零 swap，`sys` 持平），故**此处最大 RSS 是可复现的度量，footprint 则取离散值** —— 与 aggregation-rung1 §7.1 在 30 GB 级的发现相反（彼处压缩器使 RSS 成为噪声项）。每行两者皆报，取大者。

## b8 lane，可重推

`b8/q29/g22/fp16/a16`。猜想位数 = `q · β(ρ) + g`（2197 修正记法）；β 由三条已裁 lane 得出（`fri-soundness-accounting-2026-07.md` §6 表，B″ 目标精确复现）：**β(b16) = (96.9 − 22)/20 = 3.745**，**β(b4) = (96.1 − 22)/40 = 1.853**，**β(b2) = (94.8 − 22)/80 = 0.910** 位/查询。`1 − δ* = 2^−β` 给出 δ* = 0.925 / 0.723 / 0.468，即低于容量 `1 − ρ` 0.012 / 0.027 / 0.032。b8（容量 0.875）的差距夹在 b4 与 b16 之间：δ* ∈ [0.848, 0.863]，**β(b8) ∈ [2.72, 2.87]**；`q ≥ (100 − 22)/β ∈ [27.2, 28.7]` → **q29**（保守端 100.9；另一端 105.2）。ρ = 1/8 处的精确 Cor. 4.5 优化未运行。`make_config_with` 断言的容量代理：29 × 3 + 22 = 109。

## 范围内测试运行（第 0 阶段裁决 §6 —— 唯一获准的本地运行；runner 离线）

```sh
QUMBRA_RIG_OWNER=QUM-181 scripts/rig run -- ./w3-logs/scoped-tests.sh
#   = cargo test --release -p qlab-air -p qlab-note -p qlab-bench --no-fail-fast -- --test-threads=1
```

| crate | 通过 | 失败 | 忽略 | 用时 |
|---|---|---|---|---|
| `qlab-air`（lib） | **64**（37 narrow + 1 reference + **26 `l2::`**） | 0 | 0 | 1,623.8 s |
| `qlab-bench`（bin） | 113（110 + 3 `l2shape::`） | **1** — `l2shape_mock_program_is_the_padded_l1_shape`，`left: 117, right: 118` | 0 | 948.8 s |
| `qlab-note`（lib） | **39**（35 + **4 `l2note::`**） | 0 | 0 | < 0.1 s |
| doc-tests（3 组） | 0 | 0 | 0 | — |
| **合计** | **216** | **1** | 0 | 墙钟 **2,604 s**（43.4 分钟，含三个 crate 依赖的冷 release 构建）；测试二进制峰值 RSS **16.7 GB**（1 Hz `ps rss` 采样 `target/release/deps/qlab_*`） |

- 唯一失败是**测试算术**：mock 测试数了 118 个非 dummy 角色，而程序含预热 dummy 共 118 个 perm（非 dummy 117 —— 与 `SHAPE_S_PERMS = 120 = 1 + 119` 同一约定）。已在 `8a20234` 修正；修正后的该测试单独重跑（`cargo test --release -p qlab-bench l2shape_mock_program_is_the_padded_l1_shape`，持锁，获准集合的严格子集）：**1 通过，6.2 s**。
- **16.7 GB 峰值不来自 L2 测试** —— 来自 `qlab-bench` 既有的携带证明的测试（`m6devnet`/`n7soak` 驱动真实 M3 证明）；`l2shape_shape_s_prove_verify_roundtrip_b4`（经 `p3_uni_stark::prove`/`verify` 的真实 2^19 × 702 b4/q43 证明）属本文实测的 ~7 GB 级。因裁决预期个位数 GB 而申报：该 crate 承载的不止其 L2 测试。
- **26 个 `l2::` 测试占 43 分钟中的约 27 分钟** —— 每个反例迭代 16 种选择器赋值 × 一次 2^19 `check_all_constraints`。本次运行后，辅助函数改为在见证的诚实 `q` 下迭代 8 种 `(o1a, o2a, f1)`（`8a20234`），因为 `q` 的两条约束只读取捕获的 `A₁`/`A₂`，可独立拒绝（`l2_neg_q_lie_is_unsat_both_ways`）。**8 路形式是 16 路运行所执行断言的严格子集，其本身尚未执行** —— 明示而非隐藏；约减半该 crate 的 CI 时间。
- **工作区套件：未运行 — runner 离线**（#701 的 `verify-graviton` 作业自 08:25Z 起排队，无 runner 在线；第 0 阶段裁决 §6 记为欠账，非豁免）。
